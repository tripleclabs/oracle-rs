//! Fetch message for retrieving rows from a cursor
//!
//! This module implements the fetch message used to retrieve additional
//! rows from an already-executed query cursor.

use bytes::{BufMut, Bytes, BytesMut};

use crate::buffer::WriteBuffer;
use crate::capabilities::Capabilities;
use crate::constants::{
    FetchOrientation, FunctionCode, MessageType, PacketType, PACKET_HEADER_SIZE,
};
use crate::error::Result;

/// Fetch message to retrieve rows from a cursor
#[derive(Debug)]
pub struct FetchMessage {
    /// Cursor ID to fetch from
    cursor_id: u16,
    /// Number of rows to fetch
    num_rows: u32,
    /// Sequence number
    sequence_number: u8,
    /// Fetch orientation for scrollable cursors
    orientation: Option<FetchOrientation>,
    /// Fetch offset/position for scrollable cursors
    offset: i64,
}

impl FetchMessage {
    /// Create a new fetch message
    pub fn new(cursor_id: u16, num_rows: u32) -> Self {
        Self {
            cursor_id,
            num_rows,
            sequence_number: 0,
            orientation: None,
            offset: 0,
        }
    }

    /// Create a new scrollable fetch message
    pub fn new_scrollable(
        cursor_id: u16,
        num_rows: u32,
        orientation: FetchOrientation,
        offset: i64,
    ) -> Self {
        Self {
            cursor_id,
            num_rows,
            sequence_number: 0,
            orientation: Some(orientation),
            offset,
        }
    }

    /// Set the sequence number
    pub fn set_sequence_number(&mut self, seq: u8) {
        self.sequence_number = seq;
    }

    /// Build the fetch request packet
    pub fn build_request(&self, caps: &Capabilities) -> Result<Bytes> {
        self.build_request_with_sdu(caps, false)
    }

    /// Build the fetch request packet with large SDU support
    pub fn build_request_with_sdu(&self, caps: &Capabilities, large_sdu: bool) -> Result<Bytes> {
        let mut buf = WriteBuffer::new();

        // Data flags (2 bytes)
        buf.write_u16_be(0)?;

        // Write message header
        buf.write_u8(MessageType::Function as u8)?;
        buf.write_u8(FunctionCode::Fetch as u8)?;
        buf.write_u8(self.sequence_number)?;

        // Token number (required for TTC field version >= 18, i.e. Oracle 23ai)
        if caps.ttc_field_version >= 18 {
            buf.write_ub8(0)?;
        }

        // Write fetch body
        buf.write_ub4(self.cursor_id as u32)?;
        buf.write_ub4(self.num_rows)?;

        // Write scrollable cursor fields if present
        if let Some(orientation) = self.orientation {
            buf.write_ub4(orientation as u32)?; // Fetch orientation
            buf.write_ub4(self.offset as u32)?; // Fetch position (for absolute/relative)
        }

        // Build packet with header
        let payload = buf.freeze();
        let packet_len = PACKET_HEADER_SIZE + payload.len();

        let mut packet = BytesMut::with_capacity(packet_len);

        // Packet header - use 4-byte length for large SDU
        if large_sdu {
            packet.put_u32(packet_len as u32);
        } else {
            packet.put_u16(packet_len as u16); // Length
            packet.put_u16(0); // Checksum (not used for large SDU)
        }
        packet.put_u8(PacketType::Data as u8);
        packet.put_u8(0); // Flags
        packet.put_u16(0); // Header checksum

        // Payload
        packet.extend_from_slice(&payload);

        Ok(packet.freeze())
    }

    /// Get the cursor ID
    pub fn cursor_id(&self) -> u16 {
        self.cursor_id
    }

    /// Get the number of rows to fetch
    pub fn num_rows(&self) -> u32 {
        self.num_rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_message_creation() {
        let msg = FetchMessage::new(1, 100);
        assert_eq!(msg.cursor_id(), 1);
        assert_eq!(msg.num_rows(), 100);
    }

    #[test]
    fn test_fetch_message_builds_packet() {
        let msg = FetchMessage::new(1, 100);
        let caps = Capabilities::new();

        let packet = msg.build_request(&caps).unwrap();

        // Check packet header
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);

        // Check data flags are present
        assert_eq!(packet[8], 0);
        assert_eq!(packet[9], 0);

        // Check function type (byte 10) is Function (3)
        assert_eq!(packet[10], MessageType::Function as u8);

        // Check function code (byte 11) is Fetch (5)
        assert_eq!(packet[11], FunctionCode::Fetch as u8);
    }

    #[test]
    fn test_fetch_large_row_count_not_truncated() {
        let msg = FetchMessage::new(1, 100_000);
        let caps = Capabilities::new();

        let packet = msg.build_request(&caps).unwrap();

        // Header + data flags + message header + token (default caps are
        // TTC field version >= 18) + cursor id.
        let num_rows_offset = PACKET_HEADER_SIZE + 2 + 3 + 1 + 2;
        assert_eq!(
            &packet[num_rows_offset..num_rows_offset + 5],
            &[0x04, 0x00, 0x01, 0x86, 0xa0]
        );
    }

    #[test]
    fn test_fetch_token_omitted_for_pre_23ai() {
        let msg = FetchMessage::new(1, 100);
        let mut caps = Capabilities::new();
        caps.ttc_field_version = 12; // 19c

        let packet = msg.build_request(&caps).unwrap();

        // Header + data flags + message header, then directly the cursor id
        // (ub4: length 1, value 1) with no token byte in between.
        let cursor_offset = PACKET_HEADER_SIZE + 2 + 3;
        assert_eq!(&packet[cursor_offset..cursor_offset + 2], &[0x01, 0x01]);
    }

    #[test]
    fn test_fetch_large_sdu_packet_header() {
        let msg = FetchMessage::new(1, 100);
        let caps = Capabilities::new();

        let packet = msg.build_request_with_sdu(&caps, true).unwrap();

        // Large SDU mode uses a 32-bit length field instead of
        // 16-bit length + 16-bit checksum.
        let len = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        assert_eq!(len as usize, packet.len());
        assert_eq!(packet[4], PacketType::Data as u8);
    }
}
