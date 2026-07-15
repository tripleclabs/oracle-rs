//! Oracle database connection
//!
//! This module provides the main `Connection` type for interacting with Oracle databases.
//!
//! # Example
//!
//! ```rust,ignore
//! use oracle_rs::{Connection, Config};
//!
//! #[tokio::main]
//! async fn main() -> oracle_rs::Result<()> {
//!     // Create a connection
//!     let conn = Connection::connect("localhost:1521/ORCLPDB1", "user", "password").await?;
//!
//!     // Execute a query
//!     let rows = conn.query("SELECT * FROM employees WHERE department_id = :1", &[&10]).await?;
//!
//!     for row in rows {
//!         println!("{:?}", row);
//!     }
//!
//!     // Commit and close
//!     conn.commit().await?;
//!     conn.close().await?;
//!     Ok(())
//! }
//! ```

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::batch::{BatchBinds, BatchResult};
use crate::buffer::{ReadBuffer, WriteBuffer};
use crate::capabilities::Capabilities;
use crate::config::{Config, ServiceMethod};
use crate::constants::{
    version, BindDirection, FetchOrientation, FunctionCode, MessageType, OracleType, PacketType,
    PACKET_HEADER_SIZE,
};
use crate::cursor::{ScrollResult, ScrollableCursor};
use crate::error::{Error, Result};
use crate::implicit::{ImplicitResult, ImplicitResults};
use crate::messages::{
    AcceptMessage, AuthMessage, AuthPhase, ConnectMessage, ExecuteMessage, ExecuteOptions,
    FetchMessage, LobOpMessage,
};
use crate::packet::Packet;
use crate::row::{Row, Value};
use crate::statement::{BindParam, ColumnInfo, Statement, StatementType};
use crate::statement_cache::StatementCache;
use crate::transport::{connect_tls, TlsConfig, TlsOracleStream};
use crate::types::{LobData, LobLocator, LobValue};

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// TCP connection established
    Connected,
    /// Protocol negotiation complete
    ProtocolNegotiated,
    /// Data types negotiated
    DataTypesNegotiated,
    /// Fully authenticated and ready
    Ready,
    /// Connection is closed
    Closed,
}

/// Options for query execution
#[derive(Debug, Clone)]
pub struct QueryOptions {
    /// Number of rows to prefetch
    pub prefetch_rows: u32,
    /// Array size for batch operations
    pub array_size: u32,
    /// Whether to auto-commit after DML
    pub auto_commit: bool,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            prefetch_rows: 100,
            array_size: 100,
            auto_commit: false,
        }
    }
}

/// Result set from a query
#[derive(Debug)]
pub struct QueryResult {
    /// Column information
    pub columns: Vec<ColumnInfo>,
    /// Rows returned
    pub rows: Vec<Row>,
    /// Number of rows affected (for DML)
    pub rows_affected: u64,
    /// Whether there are more rows to fetch
    pub has_more_rows: bool,
    /// Cursor ID for subsequent fetches (needed for fetch_more)
    pub cursor_id: u16,
}

impl QueryResult {
    /// Create an empty query result
    pub fn empty() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 0,
        }
    }

    /// Get the number of columns
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get the number of rows
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Check if the result is empty
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Get a column by name
    pub fn column_by_name(&self, name: &str) -> Option<&ColumnInfo> {
        self.columns
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
    }

    /// Get column index by name
    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.columns
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(name))
    }

    /// Iterate over rows
    pub fn iter(&self) -> impl Iterator<Item = &Row> {
        self.rows.iter()
    }

    /// Get a single row (first row)
    pub fn first(&self) -> Option<&Row> {
        self.rows.first()
    }
}

impl IntoIterator for QueryResult {
    type Item = Row;
    type IntoIter = std::vec::IntoIter<Row>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

/// Result from executing a PL/SQL block with OUT parameters
#[derive(Debug)]
pub struct PlsqlResult {
    /// OUT parameter values indexed by position (0-based)
    pub out_values: Vec<Value>,
    /// Number of rows affected (if applicable)
    pub rows_affected: u64,
    /// Cursor ID (if the result contains a REF CURSOR)
    pub cursor_id: Option<u16>,
    /// Implicit result sets returned via DBMS_SQL.RETURN_RESULT
    pub implicit_results: ImplicitResults,
}

impl PlsqlResult {
    /// Create an empty PL/SQL result
    pub fn empty() -> Self {
        Self {
            out_values: Vec::new(),
            rows_affected: 0,
            cursor_id: None,
            implicit_results: ImplicitResults::new(),
        }
    }

    /// Get an OUT value by position (0-based)
    pub fn get(&self, index: usize) -> Option<&Value> {
        self.out_values.get(index)
    }

    /// Get a string OUT value by position
    pub fn get_string(&self, index: usize) -> Option<&str> {
        self.out_values.get(index).and_then(|v| v.as_str())
    }

    /// Get an integer OUT value by position
    pub fn get_integer(&self, index: usize) -> Option<i64> {
        self.out_values.get(index).and_then(|v| v.as_i64())
    }

    /// Get a float OUT value by position
    pub fn get_float(&self, index: usize) -> Option<f64> {
        self.out_values.get(index).and_then(|v| v.as_f64())
    }

    /// Get a cursor ID from OUT value by position (for REF CURSOR)
    pub fn get_cursor_id(&self, index: usize) -> Option<u16> {
        self.out_values.get(index).and_then(|v| v.as_cursor_id())
    }
}

/// Server information obtained during connection
#[derive(Debug, Clone, Default)]
pub struct ServerInfo {
    /// Oracle version string
    pub version: String,
    /// Server banner
    pub banner: String,
    /// Session ID (SID)
    pub session_id: u32,
    /// Serial number
    pub serial_number: u32,
    /// Instance name
    pub instance_name: Option<String>,
    /// Service name
    pub service_name: Option<String>,
    /// Database name
    pub database_name: Option<String>,
    /// Negotiated protocol version
    pub protocol_version: u16,
    /// Whether server supports OOB (out of band) data
    pub supports_oob: bool,
}

/// Stream type that can be either plain TCP or TLS-encrypted
enum OracleStream {
    /// Plain TCP connection
    Plain(TcpStream),
    /// TLS-encrypted connection
    Tls(Box<TlsOracleStream>),
}

impl OracleStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            OracleStream::Plain(stream) => {
                AsyncReadExt::read_exact(stream, buf).await?;
                Ok(())
            }
            OracleStream::Tls(stream) => {
                AsyncReadExt::read_exact(stream, buf).await?;
                Ok(())
            }
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            OracleStream::Plain(stream) => stream.write_all(buf).await,
            OracleStream::Tls(stream) => stream.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            OracleStream::Plain(stream) => stream.flush().await,
            OracleStream::Tls(stream) => stream.flush().await,
        }
    }
}

/// Internal connection state shared across async operations
struct ConnectionInner {
    stream: Option<OracleStream>,
    capabilities: Capabilities,
    state: ConnectionState,
    server_info: ServerInfo,
    sdu_size: u16,
    large_sdu: bool,
    /// Sequence number for TTC messages (increments per message)
    sequence_number: u8,
    /// Statement cache for prepared statement reuse
    statement_cache: Option<StatementCache>,
    /// Last parsed row per cursor, used to resolve duplicate-column bit vectors
    /// across fetch batch boundaries.
    fetch_seed_rows: HashMap<u16, Vec<Value>>,
}

impl ConnectionInner {
    fn new_with_cache(cache_size: usize) -> Self {
        Self {
            stream: None,
            capabilities: Capabilities::default(),
            state: ConnectionState::Disconnected,
            server_info: ServerInfo::default(),
            sdu_size: 8192,
            large_sdu: false,
            sequence_number: 0,
            statement_cache: if cache_size > 0 {
                Some(StatementCache::new(cache_size))
            } else {
                None
            },
            fetch_seed_rows: HashMap::new(),
        }
    }

    /// Get the next sequence number (auto-increments, wraps at 255 to 1)
    fn next_sequence_number(&mut self) -> u8 {
        self.sequence_number = self.sequence_number.wrapping_add(1);
        if self.sequence_number == 0 {
            self.sequence_number = 1;
        }
        self.sequence_number
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if let Some(stream) = &mut self.stream {
            stream.write_all(data).await?;
            stream.flush().await?;
            Ok(())
        } else {
            Err(Error::ConnectionClosed)
        }
    }

    /// Send a payload that may need to be split across multiple packets.
    ///
    /// This is used for large LOB writes and other operations where the payload
    /// exceeds the SDU size. The payload is split into multiple DATA packets,
    /// each with proper headers.
    ///
    /// # Arguments
    /// * `payload` - The raw message payload (without packet header or data flags)
    /// * `data_flags` - The data flags for the first packet (typically 0)
    async fn send_multi_packet(&mut self, payload: &[u8], data_flags: u16) -> Result<()> {
        let stream = self.stream.as_mut().ok_or(Error::ConnectionClosed)?;

        // Calculate max payload per packet: SDU - header (8) - data flags (2)
        let max_payload_per_packet = self.sdu_size as usize - PACKET_HEADER_SIZE - 2;

        let mut offset = 0;
        let mut is_first = true;

        while offset < payload.len() {
            let remaining = payload.len() - offset;
            let chunk_size = std::cmp::min(remaining, max_payload_per_packet);
            let is_last = offset + chunk_size >= payload.len();

            // Build packet
            let packet_len = PACKET_HEADER_SIZE + 2 + chunk_size; // header + data flags + payload
            let mut packet = Vec::with_capacity(packet_len);

            // Header
            if self.large_sdu {
                packet.extend_from_slice(&(packet_len as u32).to_be_bytes());
            } else {
                packet.extend_from_slice(&(packet_len as u16).to_be_bytes());
                packet.extend_from_slice(&[0, 0]); // Checksum
            }
            packet.push(PacketType::Data as u8);
            packet.push(0); // Flags
            packet.extend_from_slice(&[0, 0]); // Header checksum

            // Data flags - only include on first packet
            if is_first {
                packet.extend_from_slice(&data_flags.to_be_bytes());
                is_first = false;
            } else {
                // Continuation packets still need data flags position but value is 0
                packet.extend_from_slice(&0u16.to_be_bytes());
            }

            // Payload chunk
            packet.extend_from_slice(&payload[offset..offset + chunk_size]);

            // Send this packet
            stream.write_all(&packet).await?;

            offset += chunk_size;

            // Don't flush until the last packet to improve performance
            if is_last {
                stream.flush().await?;
            }
        }

        Ok(())
    }

    async fn receive(&mut self) -> Result<bytes::Bytes> {
        if let Some(stream) = &mut self.stream {
            // Read packet header first (always 8 bytes)
            // large_sdu only affects how the length field is interpreted, not header size
            let mut header_buf = vec![0u8; PACKET_HEADER_SIZE];
            stream.read_exact(&mut header_buf).await?;

            // Parse header to get payload length
            // In large_sdu mode, first 4 bytes are length; otherwise first 2 bytes
            let packet_len = if self.large_sdu {
                u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]])
                    as usize
            } else {
                u16::from_be_bytes([header_buf[0], header_buf[1]]) as usize
            };

            // Read remaining payload
            let payload_len = packet_len.saturating_sub(PACKET_HEADER_SIZE);
            let mut payload_buf = vec![0u8; payload_len];
            if payload_len > 0 {
                stream.read_exact(&mut payload_buf).await?;
            }

            // Combine header and payload
            let mut full_packet = header_buf.clone();
            full_packet.extend(payload_buf);

            Ok(bytes::Bytes::from(full_packet))
        } else {
            Err(Error::ConnectionClosed)
        }
    }

    /// Receive a complete response that may span multiple packets
    ///
    /// This method accumulates packets until the END_OF_RESPONSE flag is detected
    /// in the data flags. It's used for operations like LOB reads that may return
    /// data spanning multiple TNS packets.
    ///
    /// Returns the combined payload of all packets (excluding headers).
    async fn receive_response(&mut self) -> Result<bytes::Bytes> {
        self.receive_response_with_lob_parameter_len(None).await
    }

    async fn receive_lob_response(
        &mut self,
        lob_parameter_body_len: usize,
    ) -> Result<bytes::Bytes> {
        self.receive_response_with_lob_parameter_len(Some(lob_parameter_body_len))
            .await
    }

    async fn receive_response_with_lob_parameter_len(
        &mut self,
        lob_parameter_body_len: Option<usize>,
    ) -> Result<bytes::Bytes> {
        use crate::constants::{data_flags, MessageType};

        let legacy_11g = self.server_info.protocol_version <= version::MIN_ACCEPTED;
        let is_lob = lob_parameter_body_len.is_some();
        // Hoisted once instead of re-reading the environment on every packet.
        let debug = std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some();

        // Fast path: modern protocol (> 314), non-LOB response.
        //
        // Before Oracle 11g support was added, query/fetch/cursor/define
        // responses were read with a single receive(): modern servers negotiate
        // a large SDU and deliver each describe/prefetch/fetch batch in one TNS
        // data packet, so no accumulation is required. Crucially, servers below
        // TTC 23.4 (protocols 315-318, i.e. 12c-19c) do NOT set the
        // END_OF_RESPONSE data flag, and row/describe streams carry no in-band
        // terminator that the inspector below can recognise. An accumulation
        // loop therefore has no reliable stop condition for these responses and
        // would block forever on a complete response whose final packet happens
        // to fill the SDU exactly. Restoring the single-receive semantics for
        // modern protocols avoids that hang and matches long-standing behaviour;
        // the callers already handle MARKER packets and short responses.
        //
        // When the server DOES set the END_OF_RESPONSE data flag (protocol
        // 319+, negotiated via supports_end_of_response), that flag is a
        // deterministic terminator: accumulate DATA packets until it appears
        // so responses larger than one SDU (e.g. big fetch batches) are not
        // silently truncated at the first packet boundary.
        if !legacy_11g && !is_lob {
            if !self.capabilities.supports_end_of_response {
                return self.receive().await;
            }

            let mut accumulated = Vec::new();
            loop {
                let packet = self.receive().await?;
                if packet.len() < PACKET_HEADER_SIZE {
                    return Err(Error::Protocol("Packet too small".to_string()));
                }
                // Non-DATA packet (e.g., MARKER) - return as-is for special
                // handling by the caller.
                if packet[4] != PacketType::Data as u8 {
                    return Ok(packet);
                }
                let payload = &packet[PACKET_HEADER_SIZE..];
                if payload.len() < 2 {
                    return Err(Error::Protocol("DATA packet payload too small".to_string()));
                }
                let data_flags_value = u16::from_be_bytes([payload[0], payload[1]]);
                if accumulated.is_empty() {
                    accumulated.extend_from_slice(payload);
                } else {
                    // Subsequent packets: skip the per-packet data flags
                    accumulated.extend_from_slice(&payload[2..]);
                }
                if debug {
                    eprintln!(
                        "oracle-rs receive_response: packet {} bytes, accumulated {} bytes, \
                         data_flags={:#06x}",
                        packet.len(),
                        accumulated.len(),
                        data_flags_value,
                    );
                }
                if (data_flags_value & (data_flags::END_OF_RESPONSE | data_flags::EOF)) != 0 {
                    break;
                }
            }

            let total_len = PACKET_HEADER_SIZE + accumulated.len();
            let mut result = Vec::with_capacity(total_len);
            if self.large_sdu {
                result.extend_from_slice(&(total_len as u32).to_be_bytes());
            } else {
                result.extend_from_slice(&(total_len as u16).to_be_bytes());
                result.extend_from_slice(&[0, 0]); // Checksum
            }
            result.push(PacketType::Data as u8);
            result.push(0); // Flags
            result.extend_from_slice(&[0, 0]); // Header checksum
            result.extend_from_slice(&accumulated);
            return Ok(bytes::Bytes::from(result));
        }

        let mut accumulated_payload = Vec::new();
        let mut is_first_packet = true;
        let idle_timeout = std::time::Duration::from_secs(2);
        // Byte offset (into accumulated_payload[2..]) up to which the message
        // stream has already been fully parsed as complete messages, plus the
        // running saw_lob_data flag. These let the inspector resume from the
        // frontier each packet instead of re-scanning the whole payload (which
        // was O(N^2) for multi-packet LOB reads).
        let mut scan_offset = 0usize;
        let mut saw_lob_data = false;
        // True once the inspector has proven the stream ends mid-message and we
        // must keep reading to complete it.
        let mut incomplete = false;

        loop {
            // Choosing how to wait for the next packet:
            //
            // * When the stream is known to be mid-message (`incomplete`), we
            //   MUST block until the rest arrives. Turning slowness into an
            //   error here would discard valid accumulated data and desync the
            //   connection (the previous code raised a fatal 2s ConnectionTimeout
            //   in this situation). Blocking on genuinely incomplete data is the
            //   correct behaviour.
            // * On 11g (protocol 314) the server never sets END_OF_RESPONSE, so
            //   for responses this generic loop cannot parse to completion an
            //   idle timeout is used ONLY as a soft "no more packets are coming"
            //   signal. Its expiry is treated as end-of-response (break and
            //   return the data accumulated so far), never as an error. Row
            //   fetch responses no longer come through here at all: they use
            //   receive_fetch_response(), which has column metadata and
            //   terminates deterministically on the terminal Error/Status
            //   message instead of on silence. This loop remains for the
            //   responses without such context (initial execute/describe, DML,
            //   LOB operations), which fit in a single packet in practice.
            let packet = if !incomplete && legacy_11g && !is_first_packet {
                match tokio::time::timeout(idle_timeout, self.receive()).await {
                    Ok(result) => result?,
                    Err(_) => {
                        if debug {
                            eprintln!(
                                "oracle-rs receive_response: 11g idle timeout, treating \
                                 {} accumulated bytes as complete response",
                                accumulated_payload.len()
                            );
                        }
                        break;
                    }
                }
            } else {
                self.receive().await?
            };

            if packet.len() < PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Packet too small".to_string()));
            }

            // Check packet type - only DATA packets can be accumulated
            let packet_type = packet[4];
            if packet_type != PacketType::Data as u8 {
                // Non-DATA packet (e.g., MARKER) - return as-is for special handling
                return Ok(packet);
            }

            // Get payload (everything after the 8-byte header)
            let payload = &packet[PACKET_HEADER_SIZE..];

            if payload.len() < 2 {
                return Err(Error::Protocol("DATA packet payload too small".to_string()));
            }

            // Read data flags (first 2 bytes of payload)
            let data_flags_value = u16::from_be_bytes([payload[0], payload[1]]);

            // Check for end of response - Python checks both flags and message type
            let has_end_flag = (data_flags_value & data_flags::END_OF_RESPONSE) != 0;
            let has_eof_flag = (data_flags_value & data_flags::EOF) != 0;

            // Also check for EndOfResponse message type (header + 3 bytes with msg type 29)
            let has_end_message =
                payload.len() == 3 && payload[2] == MessageType::EndOfResponse as u8;

            // Accumulate payload first
            if is_first_packet {
                accumulated_payload.extend_from_slice(payload);
                is_first_packet = false;
            } else {
                // Subsequent packets: skip the data flags
                accumulated_payload.extend_from_slice(&payload[2..]);
            }

            // Check for end of response using data flags from this packet
            let is_end_of_response = has_end_flag || has_eof_flag || has_end_message;

            // Inspect the accumulated message data for either a terminal
            // message or a message that is clearly still split across packets.
            // The scan resumes from the previously parsed frontier so repeated
            // calls stay linear in the total payload size.
            let (has_terminal_message, has_incomplete_message) =
                if !is_end_of_response && accumulated_payload.len() > 2 {
                    self.inspect_message_stream_resumable(
                        &accumulated_payload[2..],
                        lob_parameter_body_len,
                        &mut scan_offset,
                        &mut saw_lob_data,
                    )
                } else {
                    (false, false)
                };

            // A packet smaller than the SDU often indicates the server has no
            // more data to send. Oracle 11g fills data packets to slightly
            // below the negotiated SDU (observed 8155 bytes against an SDU of
            // 8192), so "full" is detected with slack rather than equality;
            // multi-packet responses (large fetch batches, LOB chunks) would
            // otherwise be truncated at the first packet. A response whose
            // final packet lands inside the slack window is still terminated
            // correctly, by the idle timeout instead of this heuristic.
            let short_packet_slack = if legacy_11g { 64 } else { 1 };
            let is_short_packet = (packet.len() + short_packet_slack) < self.sdu_size as usize;

            if debug {
                eprintln!(
                    "oracle-rs receive_response: packet {} bytes, accumulated {} bytes, \
                     end_flag={} eof_flag={} end_msg={} terminal={} incomplete={} \
                     short={} (sdu={})",
                    packet.len(),
                    accumulated_payload.len(),
                    has_end_flag,
                    has_eof_flag,
                    has_end_message,
                    has_terminal_message,
                    has_incomplete_message,
                    is_short_packet,
                    self.sdu_size,
                );
            }

            // Deterministic completion signals first.
            if is_end_of_response || has_terminal_message {
                break;
            }
            // Stream proven to end mid-message: keep reading, and never apply the
            // short-packet heuristic (which would truncate a split message).
            if has_incomplete_message {
                incomplete = true;
                continue;
            }
            incomplete = false;
            // Heuristic completion. On 11g a short final packet is the usual
            // signal that the batch is done; the follow-up parse tolerates this
            // because 11g fetches rows in explicit batches via fetch_more() (with
            // prefetch_rows=0), so any residual/short packet is re-driven by the
            // next fetch rather than silently lost. For modern LOB reads the SDU
            // is large so is_short_packet effectively never fires here and
            // completion is driven by flags/terminal messages, matching the
            // pre-existing single-response behaviour.
            if is_short_packet {
                break;
            }
            // Full-SDU packet, no terminator, stream not flagged incomplete: on
            // 11g loop and let the idle timeout confirm end-of-response; on other
            // paths keep reading for the deferred terminal/flag.
        }

        // Build a synthetic packet with combined payload
        let total_len = PACKET_HEADER_SIZE + accumulated_payload.len();
        let mut result = Vec::with_capacity(total_len);

        // Build header
        if self.large_sdu {
            result.extend_from_slice(&(total_len as u32).to_be_bytes());
        } else {
            result.extend_from_slice(&(total_len as u16).to_be_bytes());
            result.extend_from_slice(&[0, 0]); // Checksum
        }
        result.push(PacketType::Data as u8);
        result.push(0); // Flags
        result.extend_from_slice(&[0, 0]); // Header checksum

        // Add combined payload
        result.extend_from_slice(&accumulated_payload);

        Ok(bytes::Bytes::from(result))
    }

    /// Inspect message data for terminal message types and incomplete LOB
    /// chunks. The return value is (has_terminal_message, has_incomplete_message).
    ///
    /// Thin non-resumable wrapper retained for unit tests; the receive loop
    /// calls [`Self::inspect_message_stream_resumable`] directly.
    #[cfg(test)]
    fn inspect_message_stream(&self, data: &[u8]) -> (bool, bool) {
        self.inspect_message_stream_with_lob_parameter_len(data, None)
    }

    #[cfg(test)]
    fn inspect_message_stream_with_lob_parameter_len(
        &self,
        data: &[u8],
        lob_parameter_body_len: Option<usize>,
    ) -> (bool, bool) {
        let mut offset = 0usize;
        let mut saw_lob_data = false;
        self.inspect_message_stream_resumable(
            data,
            lob_parameter_body_len,
            &mut offset,
            &mut saw_lob_data,
        )
    }

    /// Resumable variant of the message-stream inspector.
    ///
    /// `offset` is the byte position within `data` from which to resume scanning;
    /// on return it is advanced to the end of the last fully-parsed complete
    /// message so the next call (after more packets have been appended to `data`)
    /// only scans the newly-arrived bytes. `saw_lob_data` carries the "we have
    /// already seen LOB data" state across resumes, which matters for correctly
    /// classifying the trailing PARAMETER message of a LOB response.
    ///
    /// Bytes before `offset` are never rewound: they contain only complete,
    /// already-classified non-terminal messages (terminal messages and
    /// incomplete tails always cause an early return without advancing past
    /// them), so resuming from the frontier is equivalent to a full re-scan but
    /// runs in linear rather than quadratic total time.
    fn inspect_message_stream_resumable(
        &self,
        data: &[u8],
        lob_parameter_body_len: Option<usize>,
        offset: &mut usize,
        saw_lob_data: &mut bool,
    ) -> (bool, bool) {
        use crate::buffer::ReadBuffer;

        let base = (*offset).min(data.len());
        let mut buf = ReadBuffer::from_slice(&data[base..]);

        while buf.remaining() > 0 {
            let msg_type = match buf.read_u8() {
                Ok(t) => t,
                Err(_) => return (false, true),
            };

            if msg_type == MessageType::EndOfResponse as u8
                || msg_type == MessageType::Error as u8
                || msg_type == MessageType::Status as u8
            {
                return (true, false);
            }

            if msg_type == MessageType::Parameter as u8 && *saw_lob_data {
                if let Some(body_len) = lob_parameter_body_len {
                    match buf.skip(body_len) {
                        Ok(_) => return (false, false),
                        Err(Error::BufferUnderflow { .. }) => return (false, true),
                        Err(_) => return (false, false),
                    }
                } else {
                    return (false, false);
                }
            }

            if msg_type == MessageType::LobData as u8 {
                *saw_lob_data = true;
                let lob_data_result = if self.server_info.protocol_version <= version::MIN_ACCEPTED
                {
                    Self::skip_legacy_11g_lob_data(&mut buf)
                } else {
                    buf.skip_raw_bytes_chunked()
                };

                match lob_data_result {
                    Ok(_) => {
                        // This LOB chunk was fully consumed; advance the resume
                        // frontier so the next call does not re-skip it.
                        *offset = base + buf.position();
                        continue;
                    }
                    Err(Error::BufferUnderflow { .. } | Error::InvalidLengthIndicator(_)) => {
                        return (false, true);
                    }
                    Err(_) => return (false, false),
                }
            } else {
                if *saw_lob_data {
                    return (false, true);
                }
                return (false, false);
            }
        }

        if *saw_lob_data {
            return (false, true);
        }

        (false, false)
    }

    fn skip_legacy_11g_lob_data(buf: &mut ReadBuffer) -> Result<()> {
        use crate::constants::length;

        let length = buf.read_u8()?;
        if length != length::LONG_INDICATOR {
            return buf.skip(length as usize);
        }

        loop {
            let chunk_len = buf.read_u8()? as usize;
            if chunk_len == 0 {
                break;
            }
            buf.skip(chunk_len)?;
        }

        Ok(())
    }

    /// Send a marker packet with the specified marker type
    async fn send_marker(&mut self, marker_type: u8) -> Result<()> {
        let mut buf = WriteBuffer::with_capacity(16);

        // Build marker packet header
        // Marker packet structure: [length][0x00][0x00][0x00][0x0c][flags][0x00][0x00] + payload
        // Payload: [0x01][0x00][marker_type]
        let payload_len = 3; // 0x01, 0x00, marker_type
        let total_len = (PACKET_HEADER_SIZE + payload_len) as u16;

        // Header
        buf.write_u16_be(total_len)?;
        buf.write_u16_be(0)?; // zeros in large_sdu position
        buf.write_u8(PacketType::Marker as u8)?;
        buf.write_u8(0)?; // flags
        buf.write_u16_be(0)?; // reserved

        // Payload
        buf.write_u8(0x01)?; // constant
        buf.write_u8(0x00)?; // constant
        buf.write_u8(marker_type)?;

        self.send(buf.as_slice()).await
    }

    /// Handle the reset protocol after receiving a MARKER packet
    /// This sends a reset marker, waits for the reset response, then returns the error packet
    /// Returns Err if the connection is closed after reset (some Oracle versions do this)
    async fn handle_marker_reset(&mut self) -> Result<bytes::Bytes> {
        const MARKER_TYPE_RESET: u8 = 2;

        // Send reset marker
        self.send_marker(MARKER_TYPE_RESET).await?;

        // Read packets until we get a reset marker back
        loop {
            let packet = self.receive().await?;
            if packet.len() < PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Invalid packet received".to_string()));
            }

            let packet_type = packet[4];

            if packet_type == PacketType::Marker as u8 {
                // Check if it's a reset marker
                if packet.len() >= PACKET_HEADER_SIZE + 3 {
                    let marker_type = packet[PACKET_HEADER_SIZE + 2];
                    if marker_type == MARKER_TYPE_RESET {
                        break;
                    }
                }
            } else {
                // Non-marker packet received unexpectedly during reset wait
                return Ok(packet);
            }
        }

        // Try to read the error packet (may need to skip additional marker packets first)
        // Note: Some Oracle versions (like Oracle Free) may close the connection after reset
        // instead of sending an error packet
        loop {
            match self.receive().await {
                Ok(packet) => {
                    let packet_type = packet[4];

                    if packet_type != PacketType::Marker as u8 {
                        // This should be the error data packet
                        return Ok(packet);
                    }
                    // Skip additional marker packets
                }
                Err(_) => {
                    // Connection closed after reset - Oracle Free and some versions
                    // close the connection instead of sending the error details.
                    // This typically happens when:
                    // - Table or view doesn't exist
                    // - Insufficient privileges to access the object
                    // - Invalid SQL syntax
                    return Err(Error::ConnectionClosedByServer(
                        "Query failed - Oracle closed the connection without providing error details. \
                         This typically indicates insufficient privileges or the object doesn't exist.".to_string()
                    ));
                }
            }
        }
    }
}

/// An Oracle database connection.
///
/// This is the main type for interacting with Oracle databases. It provides
/// methods for executing queries, DML statements, PL/SQL blocks, and managing
/// transactions.
///
/// Connections are created using [`Connection::connect`] or
/// [`Connection::connect_with_config`]. For connection pooling, use the
/// `deadpool-oracle` crate.
///
/// # Example
///
/// ```rust,no_run
/// use oracle_rs::{Config, Connection, Value};
///
/// # async fn example() -> oracle_rs::Result<()> {
/// // Create a connection
/// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
/// let conn = Connection::connect_with_config(config).await?;
///
/// // Execute a query
/// let result = conn.query("SELECT * FROM employees WHERE dept_id = :1", &[10.into()]).await?;
/// for row in &result.rows {
///     let name = row.get_by_name("name").and_then(|v| v.as_str()).unwrap_or("");
///     println!("Employee: {}", name);
/// }
///
/// // Execute DML with transaction
/// conn.execute("INSERT INTO logs (msg) VALUES (:1)", &["Hello".into()]).await?;
/// conn.commit().await?;
///
/// // Close the connection
/// conn.close().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// `Connection` is `Send` and `Sync`, but operations are serialized internally
/// via a mutex. For parallel query execution, use multiple connections (e.g.,
/// via a connection pool).
pub struct Connection {
    inner: Arc<Mutex<ConnectionInner>>,
    config: Config,
    closed: AtomicBool,
    id: u32,
}

// Connection ID counter
static CONNECTION_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Outcome of the check-only scan over an accumulated fetch response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchScanOutcome {
    /// The terminal Error/Status message has been fully received; the
    /// response is complete.
    Terminal,
    /// The stream ends mid-message (or the terminal message has not arrived
    /// yet); more packets must be read.
    NeedMore,
    /// A message type the scanner cannot classify; fall back to heuristic
    /// termination for the rest of the response.
    Unknown,
}

/// Resumable state for [`Connection::scan_fetch_message_stream`].
///
/// `scan_offset` is the frontier (into the payload after the leading data
/// flags) up to which messages have been fully parsed; it only advances past
/// complete messages, so each scan re-examines at most one partially-received
/// message plus newly arrived bytes. `bit_vector` mirrors the running
/// duplicate-column bit vector exactly as `parse_fetch_response` tracks it,
/// because it determines how many column values the next RowData message
/// consumes from the buffer.
#[derive(Debug, Default)]
struct FetchScanState {
    scan_offset: usize,
    bit_vector: Option<Vec<u8>>,
}

impl Connection {
    /// Create a new connection to an Oracle database
    ///
    /// # Arguments
    ///
    /// * `connect_string` - Connection string in EZConnect format (e.g., "host:port/service")
    /// * `username` - Database username
    /// * `password` - Database password
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let conn = Connection::connect("localhost:1521/ORCLPDB1", "scott", "tiger").await?;
    /// ```
    pub async fn connect(connect_string: &str, username: &str, password: &str) -> Result<Self> {
        let mut config: Config = connect_string.parse()?;
        config.username = username.to_string();
        config.set_password(password);
        Self::connect_with_config(config).await
    }

    /// Create a new connection using a [`Config`].
    ///
    /// This is the preferred way to create connections as it gives full control
    /// over connection parameters including TLS, timeouts, and statement caching.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use oracle_rs::{Config, Connection};
    ///
    /// # async fn example() -> oracle_rs::Result<()> {
    /// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password")
    ///     .with_statement_cache_size(50);
    ///
    /// let conn = Connection::connect_with_config(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_with_config(config: Config) -> Result<Self> {
        let id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::Relaxed);

        // Create TCP connection
        let addr = config.socket_addr();
        let tcp_stream = TcpStream::connect(&addr).await?;

        // Set TCP options
        tcp_stream.set_nodelay(true)?;

        // Wrap with TLS if configured
        let stream = if config.is_tls_enabled() {
            let tls_config = config
                .tls_config
                .as_ref()
                .cloned()
                .unwrap_or_else(TlsConfig::new);

            let tls_stream = connect_tls(tcp_stream, &config.host, &tls_config).await?;
            OracleStream::Tls(Box::new(tls_stream))
        } else {
            OracleStream::Plain(tcp_stream)
        };

        let mut inner = ConnectionInner::new_with_cache(config.stmtcachesize);
        inner.stream = Some(stream);
        inner.state = ConnectionState::Connected;

        let conn = Connection {
            inner: Arc::new(Mutex::new(inner)),
            config,
            closed: AtomicBool::new(false),
            id,
        };

        // Perform connection handshake
        conn.perform_handshake().await?;

        Ok(conn)
    }

    /// Get the connection ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Check if the connection is closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Mark the connection as closed
    ///
    /// This should be called when the underlying connection is detected as broken.
    /// Once marked closed, `is_closed()` returns true and operations will fail fast.
    pub fn mark_closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    /// Helper to mark connection as closed if the result is a connection error
    fn handle_result<T>(&self, result: Result<T>) -> Result<T> {
        if let Err(ref e) = result {
            if e.is_connection_error() {
                self.mark_closed();
            }
        }
        result
    }

    /// Record the BitVector duplicate-column decompression seed (the last row
    /// values seen) for a cursor, so the first row of the next fetch batch can
    /// be reconstructed against it.
    ///
    /// `is_initial` must be true when this is called for a fresh (re-)execute
    /// and false for a fetch continuation. On a fresh execute that returns no
    /// prefetched rows, any seed left over from a previous execution of the
    /// same (reused) cursor id must be dropped: the next fetch starts at the
    /// first row of a brand new result set and has no previous-row seed.
    /// Leaving a continuation's stale seed in place there is only safe because a
    /// continuation that reports more rows but returns none has not advanced.
    async fn update_fetch_seed_row(
        &self,
        cursor_id: u16,
        rows: &[Row],
        has_more_rows: bool,
        is_initial: bool,
    ) {
        if cursor_id == 0 {
            return;
        }
        let mut inner = self.inner.lock().await;
        if has_more_rows {
            if let Some(last_row) = rows.last() {
                inner
                    .fetch_seed_rows
                    .insert(cursor_id, last_row.values().to_vec());
            } else if is_initial {
                inner.fetch_seed_rows.remove(&cursor_id);
            }
        } else {
            inner.fetch_seed_rows.remove(&cursor_id);
        }
    }

    async fn fetch_initial_11g_query_rows(&self, query_result: &mut QueryResult) -> Result<()> {
        let protocol_version = {
            let inner = self.inner.lock().await;
            inner.server_info.protocol_version
        };

        if protocol_version > version::MIN_ACCEPTED
            || !query_result.rows.is_empty()
            || !query_result.has_more_rows
            || query_result.cursor_id == 0
        {
            return Ok(());
        }

        let fetch_size = std::env::var("ORACLE_RS_QUERY_FETCH_ROWS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(100);
        let mut fetched_result = self
            .fetch_more(query_result.cursor_id, &query_result.columns, fetch_size)
            .await?;
        if fetched_result.columns.is_empty() {
            fetched_result.columns = query_result.columns.clone();
        }
        *query_result = fetched_result;
        Ok(())
    }

    /// Get server information
    pub async fn server_info(&self) -> ServerInfo {
        let inner = self.inner.lock().await;
        inner.server_info.clone()
    }

    /// Get the current connection state
    pub async fn state(&self) -> ConnectionState {
        let inner = self.inner.lock().await;
        inner.state
    }

    /// Perform the connection handshake
    async fn perform_handshake(&self) -> Result<()> {
        // Step 1: Send CONNECT packet and parse ACCEPT response
        self.send_connect_packet().await?;

        // Step 2: OOB check (required for protocol version >= 318 AND server supports OOB)
        // Both conditions must be met - server must have indicated OOB support in ACCEPT
        let needs_oob_check = {
            let inner = self.inner.lock().await;
            inner.server_info.protocol_version >= crate::constants::version::MIN_OOB_CHECK
                && inner.server_info.supports_oob
        };
        if needs_oob_check {
            self.send_oob_check().await?;
        }

        // Step 3: Protocol negotiation
        self.negotiate_protocol().await?;

        // Step 4: Data types negotiation
        self.negotiate_data_types().await?;

        // Step 5: Authentication
        self.authenticate().await?;

        Ok(())
    }

    /// Send OOB (Out of Band) check
    /// Required for protocol version >= 318
    async fn send_oob_check(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Step 1: Send raw byte "!" (0x21) for OOB check
        inner.send(&[0x21]).await?;

        // Step 2: Send MARKER packet with Reset
        let marker_payload = [1u8, 0u8, crate::constants::MarkerType::Reset as u8];
        let mut packet_buf = WriteBuffer::new();

        if large_sdu {
            packet_buf.write_u32_be((PACKET_HEADER_SIZE + marker_payload.len()) as u32)?;
        } else {
            packet_buf.write_u16_be((PACKET_HEADER_SIZE + marker_payload.len()) as u16)?;
            packet_buf.write_u16_be(0)?; // Checksum
        }
        packet_buf.write_u8(PacketType::Marker as u8)?;
        packet_buf.write_u8(0)?; // Flags
        packet_buf.write_u16_be(0)?; // Header checksum
        packet_buf.write_bytes(&marker_payload)?;

        inner.send(&packet_buf.freeze()).await?;

        // Step 3: Wait for OOB reset response
        // The server sends back a MARKER packet or reset acknowledgment
        let response = inner.receive().await?;

        // Validate response - should be a MARKER packet type (12)
        if response.len() > 4 && response[4] == PacketType::Marker as u8 {
            Ok(())
        } else {
            // Server might just acknowledge without a specific packet
            // This is acceptable in some Oracle versions
            Ok(())
        }
    }

    /// Send the initial CONNECT packet
    async fn send_connect_packet(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;

        // Build connect packet using ConnectMessage for proper packet format
        let connect_msg = ConnectMessage::from_config(&self.config);
        let (connect_packet, continuation) = connect_msg.build_with_continuation()?;

        // Send the CONNECT packet
        inner.send(&connect_packet).await?;

        // If we have a continuation DATA packet (for large connect strings), send it
        if let Some(ref data_packet) = continuation {
            inner.send(data_packet).await?;
        }

        const MAX_RESENDS: u8 = 3;
        let mut resend_count: u8 = 0;

        loop {
            // Wait for response
            let response = inner.receive().await?;

            // Parse response packet type
            if response.len() < PACKET_HEADER_SIZE {
                return Err(Error::PacketTooShort {
                    expected: PACKET_HEADER_SIZE,
                    actual: response.len(),
                });
            }

            let packet_type = response[4];

            match packet_type {
                2 => {
                    // ACCEPT - parse the accept message to get protocol version and capabilities
                    let packet = Packet::from_bytes(response)?;
                    let accept = AcceptMessage::parse(&packet)?;

                    // Set large_sdu mode if protocol version >= 315
                    inner.large_sdu = accept.uses_large_sdu();

                    // Update server info
                    inner.server_info.protocol_version = accept.protocol_version;
                    inner.server_info.supports_oob = accept.supports_oob;
                    inner.sdu_size = accept.sdu.min(65535) as u16;
                    inner.capabilities.adjust_for_protocol(
                        accept.protocol_version,
                        accept.service_options,
                        accept.flags2,
                    );

                    inner.state = ConnectionState::Connected;
                    return Ok(());
                }
                4 => {
                    // REFUSE
                    let mut buf = ReadBuffer::new(response.slice(PACKET_HEADER_SIZE..));
                    let _reason = buf.read_u8()?;
                    let _user_reason = buf.read_u8()?;

                    return Err(Error::ConnectionRefused {
                        error_code: None,
                        message: Some("Connection refused by server".to_string()),
                    });
                }
                5 => {
                    // REDIRECT
                    return Err(Error::ConnectionRedirect(
                        "redirect not implemented".to_string(),
                    ));
                }
                11 => {
                    // RESEND - server requests retransmission of the connect packet
                    resend_count += 1;
                    if resend_count > MAX_RESENDS {
                        return Err(Error::ProtocolError(
                            "Server requested too many resends during connect".to_string(),
                        ));
                    }
                    inner.send(&connect_packet).await?;
                    if let Some(ref data_packet) = continuation {
                        inner.send(data_packet).await?;
                    }
                }
                _ => {
                    return Err(Error::ProtocolError(format!(
                        "Unexpected packet type during connect: {}",
                        packet_type,
                    )));
                }
            }
        }
    }

    /// Negotiate protocol version and capabilities
    async fn negotiate_protocol(&self) -> Result<()> {
        use crate::messages::ProtocolMessage;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // The ACCEPT packet is the authoritative source for the negotiated
        // TTC version. Keep capabilities in sync so the 11g-specific protocol
        // builder is actually selected for TNS 314 sessions.
        inner.capabilities.protocol_version = inner.server_info.protocol_version;

        // Build protocol request (includes header)
        let protocol_msg = ProtocolMessage::new();
        let packet = protocol_msg.build_request(&inner.capabilities, large_sdu)?;
        if std::env::var_os("ORACLE_RS_DEBUG_HANDSHAKE").is_some() {
            eprintln!(
                "oracle-rs protocol request ({} bytes): {}",
                packet.len(),
                hex::encode(packet.as_ref())
            );
        }
        inner.send(&packet).await?;

        // Receive response
        let response = inner.receive().await?;
        if std::env::var_os("ORACLE_RS_DEBUG_HANDSHAKE").is_some() {
            eprintln!(
                "oracle-rs protocol response ({} bytes): {}",
                response.len(),
                hex::encode(response.as_ref())
            );
        }

        // Validate packet type (at offset 4 for both SDU modes)
        if response.len() <= 4 || response[4] != PacketType::Data as u8 {
            return Err(Error::ProtocolError(
                "Protocol negotiation failed".to_string(),
            ));
        }

        // Parse the Protocol response to extract server capabilities
        // The payload starts after the 8-byte header
        let payload = &response[PACKET_HEADER_SIZE..];
        let mut protocol_msg = ProtocolMessage::new();
        protocol_msg.parse_response(payload, &mut inner.capabilities)?;

        if std::env::var_os("ORACLE_RS_DEBUG_HANDSHAKE").is_some() {
            eprintln!(
                "oracle-rs ttc_field_version={} protocol_version={}",
                inner.capabilities.ttc_field_version, inner.capabilities.protocol_version,
            );
        }

        // Update server info with banner
        if let Some(banner) = &protocol_msg.server_banner {
            inner.server_info.banner = banner.clone();
        }

        inner.state = ConnectionState::ProtocolNegotiated;
        Ok(())
    }

    /// Negotiate data types
    async fn negotiate_data_types(&self) -> Result<()> {
        use crate::messages::DataTypesMessage;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // The legacy 11g data-types payload is keyed off the negotiated TNS
        // protocol version, so mirror the ACCEPT value here as well.
        inner.capabilities.protocol_version = inner.server_info.protocol_version;

        // Build data types request using DataTypesMessage (includes all ~320 data types)
        let data_types_msg = DataTypesMessage::new();
        let packet = data_types_msg.build_request(&inner.capabilities, large_sdu)?;
        if std::env::var_os("ORACLE_RS_DEBUG_HANDSHAKE").is_some() {
            eprintln!(
                "oracle-rs data-types request ({} bytes): {}",
                packet.len(),
                hex::encode(packet.as_ref())
            );
        }
        inner.send(&packet).await?;

        // Receive response
        let response = inner.receive().await?;
        if std::env::var_os("ORACLE_RS_DEBUG_HANDSHAKE").is_some() {
            eprintln!(
                "oracle-rs data-types response ({} bytes): {}",
                response.len(),
                hex::encode(response.as_ref())
            );
        }

        // Basic validation - packet type is at offset 4 regardless of large_sdu.
        //
        // The server echoes back the negotiated data types. That echo is
        // advisory: its parsed contents are not consumed anywhere, and the
        // request is always a single packet (build_request never produces a
        // continuation). We therefore only confirm this is a DATA packet and
        // deliberately do not parse the echoed type list, matching the
        // pre-11g behavior and tolerating server-specific layout differences
        // (e.g. Oracle 11g) rather than hard-failing connect() on a parse error.
        if response.len() > 4 && response[4] == PacketType::Data as u8 {
            inner.state = ConnectionState::DataTypesNegotiated;
            Ok(())
        } else {
            Err(Error::ProtocolError(
                "Data types negotiation failed".to_string(),
            ))
        }
    }

    /// Perform authentication
    async fn authenticate(&self) -> Result<()> {
        let service_name = match &self.config.service {
            ServiceMethod::ServiceName(name) => name.clone(),
            ServiceMethod::Sid(sid) => sid.clone(),
        };

        let mut auth = AuthMessage::new(
            &self.config.username,
            self.config.password().as_bytes(),
            &service_name,
        );
        auth.set_connect_descriptor_info(
            &self.config.host,
            self.config.port,
            matches!(self.config.service, ServiceMethod::Sid(_)),
        );

        // Phase one: send username and session info
        {
            let mut inner = self.inner.lock().await;
            let large_sdu = inner.large_sdu;
            let request = auth.build_request(&inner.capabilities, large_sdu)?;
            if std::env::var_os("ORACLE_RS_DEBUG_HANDSHAKE").is_some() {
                eprintln!(
                    "oracle-rs auth phase1 request ({} bytes): {}",
                    request.len(),
                    hex::encode(request.as_ref())
                );
            }
            inner.send(&request).await?;

            let response = inner.receive().await?;
            if std::env::var_os("ORACLE_RS_DEBUG_HANDSHAKE").is_some() {
                eprintln!(
                    "oracle-rs auth phase1 response ({} bytes): {}",
                    response.len(),
                    hex::encode(response.as_ref())
                );
            }
            if response.len() <= PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Empty auth response".to_string()));
            }

            let packet_type = response[4];
            if packet_type == PacketType::Marker as u8 {
                let error_response = inner.handle_marker_reset().await?;
                if std::env::var_os("ORACLE_RS_DEBUG_HANDSHAKE").is_some() {
                    eprintln!(
                        "oracle-rs auth phase1 marker status ({} bytes): {}",
                        error_response.len(),
                        hex::encode(error_response.as_ref())
                    );
                }
                let error_text = Self::extract_embedded_server_error(error_response.as_ref())
                    .unwrap_or_else(|| "server rejected authentication phase one".to_string());
                return Err(Error::AuthenticationFailed(error_text));
            }

            // Check for error message type
            if response.len() > PACKET_HEADER_SIZE + 2 {
                let msg_type = response[PACKET_HEADER_SIZE + 2];
                if msg_type == MessageType::Error as u8 {
                    return Err(Error::AuthenticationFailed(
                        "Server rejected authentication phase one".to_string(),
                    ));
                }
            }

            auth.parse_response(&response[PACKET_HEADER_SIZE..])?;
        }

        // Phase two: send encrypted password
        if auth.phase() == AuthPhase::Two {
            let mut inner = self.inner.lock().await;
            let large_sdu = inner.large_sdu;
            let request = auth.build_request(&inner.capabilities, large_sdu)?;
            if std::env::var_os("ORACLE_RS_DEBUG_HANDSHAKE").is_some() {
                eprintln!(
                    "oracle-rs auth phase2 request ({} bytes): {}",
                    request.len(),
                    hex::encode(request.as_ref())
                );
            }
            inner.send(&request).await?;

            let response = inner.receive().await?;
            if std::env::var_os("ORACLE_RS_DEBUG_HANDSHAKE").is_some() {
                eprintln!(
                    "oracle-rs auth phase2 response ({} bytes): {}",
                    response.len(),
                    hex::encode(response.as_ref())
                );
            }
            if response.len() <= PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Empty auth phase two response".to_string()));
            }

            // Check for error message type or marker
            let packet_type = response[4];
            if packet_type == PacketType::Marker as u8 {
                let error_response = inner.handle_marker_reset().await?;
                if std::env::var_os("ORACLE_RS_DEBUG_HANDSHAKE").is_some() {
                    eprintln!(
                        "oracle-rs auth phase2 marker status ({} bytes): {}",
                        error_response.len(),
                        hex::encode(error_response.as_ref())
                    );
                }
                let error_text = Self::extract_embedded_server_error(error_response.as_ref())
                    .unwrap_or_else(|| "server rejected authentication phase two".to_string());
                return Err(Error::AuthenticationFailed(error_text));
            }

            if response.len() > PACKET_HEADER_SIZE + 2 {
                let msg_type = response[PACKET_HEADER_SIZE + 2];
                if msg_type == MessageType::Error as u8 {
                    return Err(Error::InvalidCredentials);
                }
            }

            auth.parse_response(&response[PACKET_HEADER_SIZE..])?;
        }

        // Verify authentication completed
        if !auth.is_complete() {
            return Err(Error::AuthenticationFailed(
                "Authentication did not complete".to_string(),
            ));
        }

        let session_identifiers = auth.session_identifiers();

        // Store combo key for later use (encrypted data)
        let mut inner = self.inner.lock().await;
        if let Some(combo_key) = auth.combo_key() {
            inner.capabilities.combo_key = Some(combo_key.to_vec());
        }
        if let Some((session_id, serial_number, _failover_id)) = session_identifiers {
            inner.server_info.session_id = session_id;
            inner.server_info.serial_number = serial_number;
        }
        inner.sequence_number = 2;

        if inner.server_info.protocol_version <= version::MIN_ACCEPTED {
            let mut ver_buf = crate::buffer::WriteBuffer::with_capacity(32);
            ver_buf.write_zeros(PACKET_HEADER_SIZE)?;
            ver_buf.write_u16_be(0)?;
            ver_buf.write_u8(MessageType::Function as u8)?;
            ver_buf.write_u8(FunctionCode::VersionNewFormat as u8)?;
            ver_buf.write_u8(0)?;
            ver_buf.write_u8(1)?;
            ver_buf.write_ub2(0x100)?;
            ver_buf.write_u8(1)?;
            ver_buf.write_u8(1)?;
            let total_len = ver_buf.len() as u32;
            let header = crate::packet::PacketHeader::new(PacketType::Data, total_len);
            let mut hdr_buf = crate::buffer::WriteBuffer::with_capacity(PACKET_HEADER_SIZE);
            header.write(&mut hdr_buf, inner.large_sdu)?;
            let mut packet = ver_buf.into_inner();
            packet[..PACKET_HEADER_SIZE].copy_from_slice(hdr_buf.as_slice());
            inner.send(&packet.freeze()).await?;
            let _ = inner.receive().await?;
        }

        inner.state = ConnectionState::Ready;

        Ok(())
    }

    /// Execute a SQL statement and return the result
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL statement to execute
    /// * `params` - Bind parameters (use `Value::Integer`, `Value::String`, etc.)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::Value;
    ///
    /// // Query with bind parameters
    /// let result = conn.execute(
    ///     "SELECT * FROM employees WHERE department_id = :1",
    ///     &[Value::Integer(10)]
    /// ).await?;
    ///
    /// // DML with bind parameters
    /// let result = conn.execute(
    ///     "UPDATE employees SET salary = :1 WHERE employee_id = :2",
    ///     &[Value::Integer(50000), Value::Integer(100)]
    /// ).await?;
    /// println!("Rows affected: {}", result.rows_affected);
    /// ```
    pub async fn execute(&self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        self.ensure_ready().await?;

        // Check statement cache for existing prepared statement
        let (statement, from_cache) = {
            let mut inner = self.inner.lock().await;
            if let Some(ref mut cache) = inner.statement_cache {
                if let Some(cached_stmt) = cache.get(sql) {
                    tracing::trace!(
                        sql = sql,
                        cursor_id = cached_stmt.cursor_id(),
                        "Using cached statement (execute)"
                    );
                    (cached_stmt, true)
                } else {
                    (Statement::new(sql), false)
                }
            } else {
                (Statement::new(sql), false)
            }
        };

        let mut result = match statement.statement_type() {
            StatementType::Query => self.execute_query_with_params(&statement, params).await,
            _ => self.execute_dml_with_params(&statement, params).await,
        };

        if let Ok(ref mut query_result) = result {
            if let Err(err) = self.fetch_initial_11g_query_rows(query_result).await {
                result = Err(err);
            }
        }

        // Seed (or reset) the BitVector decompression seed for this cursor, so a
        // following fetch_more() against execute()-prefetched rows decompresses
        // correctly and a re-execute never inherits a prior execution's seed.
        if let Ok(ref query_result) = result {
            self.update_fetch_seed_row(
                query_result.cursor_id,
                &query_result.rows,
                query_result.has_more_rows,
                true,
            )
            .await;
        }

        // Return statement to cache or cache it for the first time
        match &result {
            Ok(query_result) => {
                let mut inner = self.inner.lock().await;
                if let Some(ref mut cache) = inner.statement_cache {
                    let should_close_cursor = if statement.statement_type() == StatementType::Query
                    {
                        !query_result.has_more_rows
                    } else {
                        true // DML/DDL/PL-SQL: always close
                    };

                    if from_cache {
                        cache.return_statement(sql);
                        if should_close_cursor {
                            cache.mark_cursor_closed(sql);
                        }
                    } else if query_result.cursor_id > 0 && !statement.is_ddl() {
                        let mut stmt_to_cache = statement.clone();
                        stmt_to_cache.set_cursor_id(query_result.cursor_id);
                        stmt_to_cache.set_executed(true);
                        cache.put(sql.to_string(), stmt_to_cache);
                        if should_close_cursor {
                            cache.mark_cursor_closed(sql);
                        }
                    }
                }
            }
            Err(_) => {
                if from_cache {
                    let mut inner = self.inner.lock().await;
                    if let Some(ref mut cache) = inner.statement_cache {
                        cache.return_statement(sql);
                        cache.mark_cursor_closed(sql);
                    }
                }
            }
        }

        result
    }

    /// Execute a query and return rows
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::Value;
    ///
    /// let result = conn.query(
    ///     "SELECT * FROM employees WHERE salary > :1",
    ///     &[Value::Integer(50000)]
    /// ).await?;
    /// ```
    pub async fn query(&self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        self.ensure_ready().await?;

        // Check statement cache for existing prepared statement
        let (statement, from_cache) = {
            let mut inner = self.inner.lock().await;
            if let Some(ref mut cache) = inner.statement_cache {
                if let Some(cached_stmt) = cache.get(sql) {
                    tracing::trace!(
                        sql = sql,
                        cursor_id = cached_stmt.cursor_id(),
                        "Using cached statement"
                    );
                    (cached_stmt, true)
                } else {
                    (Statement::new(sql), false)
                }
            } else {
                (Statement::new(sql), false)
            }
        };

        // If using cached statement, save the columns (Oracle won't resend on reexecute)
        let cached_columns = if from_cache {
            Some(statement.columns().to_vec())
        } else {
            None
        };

        let mut result = self.execute_query_with_params(&statement, params).await;

        // For cached statements, restore columns if Oracle didn't send them
        if let (Ok(ref mut query_result), Some(columns)) = (&mut result, cached_columns) {
            if query_result.columns.is_empty() && !columns.is_empty() {
                query_result.columns = columns;
            }
        }

        if let Ok(ref mut query_result) = result {
            if let Err(err) = self.fetch_initial_11g_query_rows(query_result).await {
                result = Err(err);
            }
        }

        if let Ok(ref query_result) = result {
            self.update_fetch_seed_row(
                query_result.cursor_id,
                &query_result.rows,
                query_result.has_more_rows,
                true,
            )
            .await;
        }

        // Return statement to cache or cache it for the first time
        match &result {
            Ok(query_result) => {
                let mut inner = self.inner.lock().await;
                if let Some(ref mut cache) = inner.statement_cache {
                    if from_cache {
                        cache.return_statement(sql);
                        if !query_result.has_more_rows {
                            cache.mark_cursor_closed(sql);
                        }
                    } else if query_result.cursor_id > 0 && !statement.is_ddl() {
                        let mut stmt_to_cache = statement.clone();
                        stmt_to_cache.set_cursor_id(query_result.cursor_id);
                        stmt_to_cache.set_executed(true);
                        stmt_to_cache.set_columns(query_result.columns.clone());
                        cache.put(sql.to_string(), stmt_to_cache);
                        if !query_result.has_more_rows {
                            cache.mark_cursor_closed(sql);
                        }
                    }
                }
            }
            Err(_) => {
                if from_cache {
                    let mut inner = self.inner.lock().await;
                    if let Some(ref mut cache) = inner.statement_cache {
                        cache.return_statement(sql);
                        cache.mark_cursor_closed(sql);
                    }
                }
            }
        }

        self.handle_result(result)
    }

    /// Execute DML (INSERT, UPDATE, DELETE) and return rows affected
    pub async fn execute_dml_sql(&self, sql: &str, params: &[Value]) -> Result<u64> {
        self.ensure_ready().await?;

        // Check statement cache for existing prepared statement
        let (statement, from_cache) = {
            let mut inner = self.inner.lock().await;
            if let Some(ref mut cache) = inner.statement_cache {
                if let Some(cached_stmt) = cache.get(sql) {
                    tracing::trace!(
                        sql = sql,
                        cursor_id = cached_stmt.cursor_id(),
                        "Using cached DML statement"
                    );
                    (cached_stmt, true)
                } else {
                    (Statement::new(sql), false)
                }
            } else {
                (Statement::new(sql), false)
            }
        };

        let result = self.execute_dml_with_params(&statement, params).await;

        // Return statement to cache or cache it for the first time
        // DML cursors are always closed after execution (no fetch phase)
        match &result {
            Ok(query_result) => {
                let mut inner = self.inner.lock().await;
                if let Some(ref mut cache) = inner.statement_cache {
                    if from_cache {
                        cache.return_statement(sql);
                        cache.mark_cursor_closed(sql);
                    } else if query_result.cursor_id > 0 && !statement.is_ddl() {
                        let mut stmt_to_cache = statement.clone();
                        stmt_to_cache.set_cursor_id(query_result.cursor_id);
                        stmt_to_cache.set_executed(true);
                        cache.put(sql.to_string(), stmt_to_cache);
                        cache.mark_cursor_closed(sql);
                    }
                }
            }
            Err(_) => {
                if from_cache {
                    let mut inner = self.inner.lock().await;
                    if let Some(ref mut cache) = inner.statement_cache {
                        cache.return_statement(sql);
                        cache.mark_cursor_closed(sql);
                    }
                }
            }
        }

        self.handle_result(result).map(|r| r.rows_affected)
    }

    /// Execute a PL/SQL block with IN/OUT/INOUT parameters
    ///
    /// This method allows execution of PL/SQL anonymous blocks or procedure calls
    /// that have OUT or IN OUT parameters. The `params` slice specifies the direction
    /// and type of each bind parameter.
    ///
    /// # Arguments
    ///
    /// * `sql` - The PL/SQL block or procedure call
    /// * `params` - The bind parameters with direction information
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::{Connection, BindParam, OracleType, Value};
    ///
    /// // Call a procedure with IN and OUT parameters
    /// let result = conn.execute_plsql(
    ///     "BEGIN get_employee_name(:1, :2); END;",
    ///     &[
    ///         BindParam::input(Value::Integer(100)),           // IN: employee_id
    ///         BindParam::output(OracleType::Varchar, 100),     // OUT: employee_name
    ///     ]
    /// ).await?;
    ///
    /// // Get the OUT parameter value
    /// let name = result.get_string(0).unwrap_or("Unknown");
    /// println!("Employee name: {}", name);
    /// ```
    ///
    /// # REF CURSOR Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::{Connection, BindParam, Value};
    ///
    /// // Call a procedure that returns a REF CURSOR
    /// let result = conn.execute_plsql(
    ///     "BEGIN OPEN :1 FOR SELECT * FROM employees; END;",
    ///     &[BindParam::output_cursor()]
    /// ).await?;
    ///
    /// // Get the cursor ID and fetch rows
    /// if let Some(cursor_id) = result.get_cursor_id(0) {
    ///     let rows = conn.fetch_cursor(cursor_id, 100).await?;
    ///     for row in rows {
    ///         println!("{:?}", row);
    ///     }
    /// }
    /// ```
    pub async fn execute_plsql(&self, sql: &str, params: &[BindParam]) -> Result<PlsqlResult> {
        self.ensure_ready().await?;

        let statement = Statement::new(sql);

        // Build values for bind parameters
        // IN params: use provided value or Null
        // OUT params: use placeholder value (required for metadata, server ignores actual value)
        // INOUT params: use provided value or Null
        let bind_values: Vec<Value> = params
            .iter()
            .map(|p| {
                if p.direction == BindDirection::Output {
                    // OUT params get a placeholder based on their type
                    // Oracle still needs a value sent in the request (even though it's ignored)
                    p.placeholder_value()
                } else {
                    // IN and INOUT params use the provided value or Null
                    p.value.clone().unwrap_or(Value::Null)
                }
            })
            .collect();

        // Build bind metadata for proper buffer sizes
        // For OUTPUT params, use the user-specified buffer_size
        // For INPUT params, derive buffer_size from the actual value
        let bind_metadata: Vec<crate::messages::BindMetadata> = params
            .iter()
            .zip(bind_values.iter())
            .map(|(p, v)| {
                let buffer_size = if p.buffer_size > 0 {
                    p.buffer_size
                } else {
                    // Derive from value
                    match v {
                        Value::String(s) => std::cmp::max(s.len() as u32, 1),
                        Value::Bytes(b) => std::cmp::max(b.len() as u32, 1),
                        Value::Integer(_) | Value::Number(_) => 22, // Oracle NUMBER max size
                        Value::Float(_) => 8,                       // BINARY_DOUBLE
                        Value::Boolean(_) => 1,
                        Value::Timestamp(_) => 13,
                        Value::Date(_) => 7,
                        Value::RowId(_) => 18,
                        _ => 100, // Default fallback
                    }
                };
                crate::messages::BindMetadata {
                    oracle_type: p.oracle_type,
                    buffer_size,
                }
            })
            .collect();

        // Create execute message with PL/SQL options
        let options = ExecuteOptions::for_plsql();
        let mut execute_msg = ExecuteMessage::new(&statement, options);
        execute_msg.set_bind_values(bind_values);
        execute_msg.set_bind_metadata(bind_metadata);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        if std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some() {
            eprintln!(
                "oracle-rs query request ({} bytes): {}",
                request.len(),
                hex::encode(request.as_ref())
            );
        }
        inner.send(&request).await?;

        // Receive response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty PL/SQL response".to_string()));
        }

        // Check for MARKER packet (indicates error - requires reset protocol)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Handle marker reset protocol and get the error packet
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            // Parse error response to extract the actual Oracle error
            let _: QueryResult = self.parse_error_response(payload)?;
            return Err(Error::Protocol("PL/SQL execution failed".to_string()));
        }

        // Parse the PL/SQL response
        let payload = &response[PACKET_HEADER_SIZE..];
        let caps = inner.capabilities.clone();
        drop(inner); // Release lock before parsing

        self.parse_plsql_response(payload, &caps, params)
    }

    /// Execute a batch of DML statements with multiple rows of bind values
    ///
    /// This method efficiently executes the same SQL statement multiple times
    /// with different bind values (executemany pattern).
    ///
    /// # Arguments
    ///
    /// * `batch` - The batch containing SQL and rows of bind values
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::{Connection, BatchBuilder, Value};
    ///
    /// let batch = BatchBuilder::new("INSERT INTO users (id, name) VALUES (:1, :2)")
    ///     .add_row(vec![Value::Integer(1), Value::String("Alice".to_string())])
    ///     .add_row(vec![Value::Integer(2), Value::String("Bob".to_string())])
    ///     .with_row_counts()
    ///     .build();
    ///
    /// let result = conn.execute_batch(&batch).await?;
    /// println!("Total rows affected: {}", result.total_rows_affected);
    /// ```
    pub async fn execute_batch(&self, batch: &BatchBinds) -> Result<BatchResult> {
        self.ensure_ready().await?;

        // Validate the batch
        batch.validate()?;

        if batch.rows.is_empty() {
            return Ok(BatchResult::new());
        }

        // Build execute options for batch DML
        let mut options = ExecuteOptions::for_dml(batch.options.auto_commit);
        options.num_execs = batch.rows.len() as u32;
        options.batch_errors = batch.options.batch_errors;
        options.dml_row_counts = batch.options.array_dml_row_counts;

        // Create execute message with batch bind values
        let mut execute_msg = ExecuteMessage::new(&batch.statement, options);
        execute_msg.set_batch_bind_values(batch.rows.clone());

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        if std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some() {
            eprintln!(
                "oracle-rs query request ({} bytes): {}",
                request.len(),
                hex::encode(request.as_ref())
            );
        }
        inner.send(&request).await?;

        // Receive response
        let mut response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty batch response".to_string()));
        }

        // Check packet type - handle MARKER packets
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Handle BREAK/RESET protocol same as regular DML
            response = self.handle_marker_protocol(&mut inner, response).await?;
        }

        // Parse the batch response
        let payload = &response[PACKET_HEADER_SIZE..];
        let ttc_field_version = inner.capabilities.ttc_field_version;
        drop(inner); // Release lock before parsing

        self.parse_batch_response(
            payload,
            batch.rows.len(),
            batch.options.array_dml_row_counts,
            ttc_field_version,
        )
    }

    /// Handle MARKER packet protocol (BREAK/RESET)
    async fn handle_marker_protocol(
        &self,
        inner: &mut ConnectionInner,
        initial_response: Bytes,
    ) -> Result<Bytes> {
        // Extract marker type from packet
        let marker_type = if initial_response.len() >= PACKET_HEADER_SIZE + 3 {
            initial_response[PACKET_HEADER_SIZE + 2]
        } else {
            1 // Assume BREAK
        };

        if marker_type == 1 {
            // BREAK marker - send RESET and wait for response
            self.send_marker(inner, 2).await?;

            // Wait for RESET marker back
            loop {
                match inner.receive().await {
                    Ok(pkt) => {
                        if pkt.len() < PACKET_HEADER_SIZE + 1 {
                            break;
                        }
                        let pkt_type = pkt[4];
                        if pkt_type == PacketType::Marker as u8 {
                            if pkt.len() >= PACKET_HEADER_SIZE + 3 {
                                let mk_type = pkt[PACKET_HEADER_SIZE + 2];
                                if mk_type == 2 {
                                    // Got RESET marker, break out
                                    break;
                                }
                            }
                        } else if pkt_type == PacketType::Data as u8 {
                            // Got DATA packet - return it as the response
                            return Ok(pkt);
                        } else {
                            break;
                        }
                    }
                    Err(e) => {
                        inner.state = ConnectionState::Closed;
                        return Err(e);
                    }
                }
            }

            // After RESET, continue receiving until we get DATA packet
            loop {
                match inner.receive().await {
                    Ok(pkt) => {
                        let pkt_type = pkt[4];
                        if pkt_type == PacketType::Marker as u8 {
                            continue;
                        } else if pkt_type == PacketType::Data as u8 {
                            return Ok(pkt);
                        } else {
                            return Err(Error::Protocol(format!(
                                "Unexpected packet type {} after reset",
                                pkt_type
                            )));
                        }
                    }
                    Err(e) => {
                        inner.state = ConnectionState::Closed;
                        return Err(e);
                    }
                }
            }
        }

        Ok(initial_response)
    }

    /// Parse batch execution response
    fn parse_batch_response(
        &self,
        payload: &[u8],
        batch_size: usize,
        want_row_counts: bool,
        ttc_field_version: u8,
    ) -> Result<BatchResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("Batch response too short".to_string()));
        }

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut rows_affected: u64 = 0;
        let mut row_counts: Option<Vec<u64>> = None;
        let mut end_of_response = false;

        // Process messages until end_of_response or out of data
        while !end_of_response && buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Error (4) - may contain error or success info
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, _cid, row_count) =
                        self.parse_error_info_with_rowcount(&mut buf, ttc_field_version)?;
                    rows_affected = row_count;
                    if error_code != 0 && error_code != 1403 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                }

                // Parameter (8) - return parameters (may contain row counts)
                x if x == MessageType::Parameter as u8 => {
                    let supports_array_row_counts =
                        ttc_field_version >= crate::constants::ccap_value::FIELD_VERSION_12_1;
                    if let Some(counts) = self.parse_return_parameters_internal(
                        &mut buf,
                        want_row_counts && supports_array_row_counts,
                    )? {
                        row_counts = Some(counts);
                    }
                }

                // Status (9) - call status
                x if x == MessageType::Status as u8 => {
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                }

                // BitVector (21)
                21 => {
                    let _num_columns_sent = buf.read_ub2()?;
                    if buf.remaining() > 0 {
                        let _byte = buf.read_u8()?;
                    }
                }

                // End of Response (29) - explicit end marker
                29 => {
                    end_of_response = true;
                }

                _ => {
                    // Unknown message type - continue processing
                }
            }
        }

        let mut result = BatchResult::new();
        result.total_rows_affected = rows_affected;
        result.success_count = batch_size;
        result.row_counts = row_counts;

        Ok(result)
    }

    /// Last-resort deadline for [`Self::receive_fetch_response`]. Its expiry
    /// is a loud error, never a silently truncated "complete" response, so it
    /// only needs to be large enough to never fire on a healthy connection.
    fn fetch_response_deadline() -> std::time::Duration {
        std::env::var("ORACLE_RS_FETCH_RESPONSE_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .map(std::time::Duration::from_secs)
            .unwrap_or_else(|| std::time::Duration::from_secs(120))
    }

    /// Receive a complete fetch response using parse-driven termination.
    ///
    /// Every fetch round trip, on every supported server version, ends with
    /// an in-band terminal message: an Error message carrying the end-of-call
    /// status (error 0 = success/more rows, ORA-1403 = end of data) or a
    /// Status message. A fetch response is therefore complete exactly when
    /// that message has been fully received — never before, and never because
    /// of how the server happened to packetize it. Column metadata makes the
    /// row-bearing messages parseable here, which the generic inspector used
    /// by `receive_response` cannot do, so this loop never has to guess from
    /// packet sizes or inter-packet silence:
    ///
    /// * scanner says the stream ends mid-message or the terminal message has
    ///   not arrived → block for the next packet (the server has more to
    ///   send; turning slowness into truncation here is what previously lost
    ///   rows and desynced the delta-encoded 11g row stream);
    /// * scanner reaches the terminal message (or, on 23ai+, the server sets
    ///   the END_OF_RESPONSE data flag) → response complete;
    /// * scanner meets a message type it cannot classify → fall back to the
    ///   pre-existing heuristics (short packet, 11g idle timeout) rather than
    ///   risk stalling on an unknown stream shape.
    async fn receive_fetch_response(
        &self,
        inner: &mut ConnectionInner,
        columns: &[ColumnInfo],
    ) -> Result<bytes::Bytes> {
        use crate::constants::data_flags;

        // 23ai+ delimits responses with the END_OF_RESPONSE data flag; the
        // flag-driven accumulation in receive_response() is already
        // deterministic there and also consumes messages that trail the
        // error info (which stopping at the terminal message would cut
        // short, leaving unread packets to desync the next call).
        if inner.capabilities.supports_end_of_response {
            return inner.receive_response().await;
        }

        let debug = std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some();
        let caps = inner.capabilities.clone();
        let legacy_11g = inner.server_info.protocol_version <= version::MIN_ACCEPTED;
        let overall_deadline = Self::fetch_response_deadline();
        let deadline = tokio::time::Instant::now() + overall_deadline;
        let idle_timeout = std::time::Duration::from_secs(2);

        let mut accumulated_payload: Vec<u8> = Vec::new();
        let mut is_first_packet = true;
        let mut scan_state = FetchScanState::default();
        let mut scan_broken = false;

        loop {
            let packet = if scan_broken && legacy_11g && !is_first_packet {
                // Heuristic fallback only: on 11g an idle gap is taken as
                // end-of-response, matching the pre-existing behaviour of
                // receive_response() for streams we cannot classify.
                match tokio::time::timeout(idle_timeout, inner.receive()).await {
                    Ok(result) => result?,
                    Err(_) => break,
                }
            } else {
                match tokio::time::timeout_at(deadline, inner.receive()).await {
                    Ok(result) => result?,
                    Err(_) => {
                        // The response is provably incomplete (the terminal
                        // message has not arrived). Treating it as complete
                        // would silently drop rows; fail loudly instead. The
                        // connection may be left mid-response, which is why
                        // this maps to a fatal connection error.
                        return Err(Error::ConnectionTimeout(overall_deadline));
                    }
                }
            };

            if packet.len() < PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Packet too small".to_string()));
            }
            // Non-DATA packet (e.g., MARKER) - return as-is for special
            // handling by the caller.
            if packet[4] != PacketType::Data as u8 {
                return Ok(packet);
            }
            let payload = &packet[PACKET_HEADER_SIZE..];
            if payload.len() < 2 {
                return Err(Error::Protocol("DATA packet payload too small".to_string()));
            }
            let data_flags_value = u16::from_be_bytes([payload[0], payload[1]]);
            let has_end_flag =
                (data_flags_value & (data_flags::END_OF_RESPONSE | data_flags::EOF)) != 0;
            let has_end_message =
                payload.len() == 3 && payload[2] == MessageType::EndOfResponse as u8;

            if is_first_packet {
                accumulated_payload.extend_from_slice(payload);
                is_first_packet = false;
            } else {
                // Subsequent packets: skip the per-packet data flags
                accumulated_payload.extend_from_slice(&payload[2..]);
            }

            if has_end_flag || has_end_message {
                break;
            }

            if !scan_broken && accumulated_payload.len() > 2 {
                let outcome = self.scan_fetch_message_stream(
                    &accumulated_payload[2..],
                    columns,
                    &caps,
                    &mut scan_state,
                );
                if debug {
                    eprintln!(
                        "oracle-rs receive_fetch_response: packet {} bytes, accumulated {} \
                         bytes, scan={:?}, frontier={}",
                        packet.len(),
                        accumulated_payload.len(),
                        outcome,
                        scan_state.scan_offset,
                    );
                }
                match outcome {
                    FetchScanOutcome::Terminal => break,
                    FetchScanOutcome::NeedMore => continue,
                    FetchScanOutcome::Unknown => scan_broken = true,
                }
            }

            // Heuristic termination for streams the scanner cannot classify
            // (pre-existing receive_response() behaviour).
            if !legacy_11g {
                break;
            }
            let short_packet_slack = 64usize;
            if packet.len() + short_packet_slack < inner.sdu_size as usize {
                break;
            }
            // Full-sized 11g packet: loop; the idle timeout above concludes
            // the response if no further packet arrives.
        }

        // Build a synthetic packet with combined payload
        let total_len = PACKET_HEADER_SIZE + accumulated_payload.len();
        let mut result = Vec::with_capacity(total_len);
        if inner.large_sdu {
            result.extend_from_slice(&(total_len as u32).to_be_bytes());
        } else {
            result.extend_from_slice(&(total_len as u16).to_be_bytes());
            result.extend_from_slice(&[0, 0]); // Checksum
        }
        result.push(PacketType::Data as u8);
        result.push(0); // Flags
        result.extend_from_slice(&[0, 0]); // Header checksum
        result.extend_from_slice(&accumulated_payload);
        Ok(bytes::Bytes::from(result))
    }

    /// Check-only walk over the message stream of an accumulated fetch
    /// response, mirroring exactly what `parse_fetch_response` will consume.
    ///
    /// `data` is the accumulated payload after the leading data flags. Only
    /// `Error::BufferUnderflow` is treated as "more data needed": it is the
    /// one error that appending bytes can cure. Any other parse failure is
    /// deterministic content corruption, so the buffer is delivered
    /// (`Terminal`) and the real parse surfaces the same error.
    fn scan_fetch_message_stream(
        &self,
        data: &[u8],
        columns: &[ColumnInfo],
        caps: &Capabilities,
        state: &mut FetchScanState,
    ) -> FetchScanOutcome {
        let base = state.scan_offset.min(data.len());
        let mut buf = ReadBuffer::from_slice(&data[base..]);

        while buf.remaining() > 0 {
            let msg_type = match buf.read_u8() {
                Ok(t) => t,
                Err(_) => return FetchScanOutcome::NeedMore,
            };

            if msg_type == MessageType::Error as u8 {
                return match self.parse_error_message_info(&mut buf, caps.ttc_field_version) {
                    Err(Error::BufferUnderflow { .. }) => FetchScanOutcome::NeedMore,
                    _ => FetchScanOutcome::Terminal,
                };
            }
            if msg_type == MessageType::Status as u8 || msg_type == MessageType::EndOfResponse as u8
            {
                return FetchScanOutcome::Terminal;
            }

            if msg_type == MessageType::RowHeader as u8 {
                match Self::scan_row_header(&mut buf) {
                    Ok(Some(bv)) => state.bit_vector = Some(bv),
                    Ok(None) => {}
                    Err(Error::BufferUnderflow { .. }) => return FetchScanOutcome::NeedMore,
                    Err(_) => return FetchScanOutcome::Terminal,
                }
            } else if msg_type == MessageType::RowData as u8 {
                match self.parse_row_data_with_bitvector(
                    &mut buf,
                    columns,
                    caps,
                    state.bit_vector.as_deref(),
                    None,
                ) {
                    Ok(_) => state.bit_vector = None,
                    Err(Error::BufferUnderflow { .. }) => return FetchScanOutcome::NeedMore,
                    Err(_) => return FetchScanOutcome::Terminal,
                }
            } else if msg_type == MessageType::BitVector as u8 {
                match Self::scan_bit_vector(&mut buf, columns.len()) {
                    Ok(Some(bv)) => state.bit_vector = Some(bv),
                    Ok(None) => {}
                    Err(Error::BufferUnderflow { .. }) => return FetchScanOutcome::NeedMore,
                    Err(_) => return FetchScanOutcome::Terminal,
                }
            } else {
                return FetchScanOutcome::Unknown;
            }

            state.scan_offset = base + buf.position();
        }

        // All accumulated bytes form complete messages but the terminal
        // Error/Status message has not arrived yet: more packets are coming.
        FetchScanOutcome::NeedMore
    }

    /// Structural skip of a RowHeader message body, byte-for-byte identical
    /// to the RowHeader arm of `parse_fetch_response`. Returns the bit vector
    /// if the header carried one.
    fn scan_row_header(buf: &mut ReadBuffer) -> Result<Option<Vec<u8>>> {
        buf.skip(1)?; // flags
        buf.skip_ub2()?; // num requests
        buf.skip_ub4()?; // iteration number
        buf.skip_ub4()?; // num iters
        buf.skip_ub2()?; // buffer length
        let num_bytes = buf.read_ub4()?;
        let bit_vector = if num_bytes > 0 {
            buf.skip(1)?; // repeated length
            Some(buf.read_bytes_vec(num_bytes as usize)?)
        } else {
            None
        };
        let rxhrid_bytes = buf.read_ub4()?;
        if rxhrid_bytes > 0 {
            buf.skip_raw_bytes_chunked()?;
        }
        Ok(bit_vector)
    }

    /// Structural skip of a BitVector message body, byte-for-byte identical
    /// to the BitVector arm of `parse_fetch_response`.
    fn scan_bit_vector(buf: &mut ReadBuffer, num_columns: usize) -> Result<Option<Vec<u8>>> {
        buf.read_ub2()?; // num columns sent
        let num_bytes = (num_columns + 7) / 8;
        if num_bytes > 0 {
            Ok(Some(buf.read_bytes_vec(num_bytes)?))
        } else {
            Ok(None)
        }
    }

    /// Fetch more rows from an open cursor
    ///
    /// This method is used when a query result has `has_more_rows == true`
    /// to retrieve additional rows from the server.
    ///
    /// # Arguments
    ///
    /// * `cursor_id` - The cursor ID from a previous query result
    /// * `columns` - Column information from the original query
    /// * `fetch_size` - Number of rows to fetch
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut result = conn.query("SELECT * FROM large_table", &[]).await?;
    /// let mut all_rows = result.rows.clone();
    ///
    /// while result.has_more_rows {
    ///     result = conn.fetch_more(result.cursor_id, &result.columns, 100).await?;
    ///     all_rows.extend(result.rows);
    /// }
    /// ```
    pub async fn fetch_more(
        &self,
        cursor_id: u16,
        columns: &[ColumnInfo],
        fetch_size: u32,
    ) -> Result<QueryResult> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let protocol_version = inner.server_info.protocol_version;
        let previous_values = inner.fetch_seed_rows.get(&cursor_id).cloned();
        let request = if protocol_version <= version::MIN_ACCEPTED {
            use crate::messages::ExecuteMessage;

            let mut stmt = Statement::new("");
            stmt.set_cursor_id(cursor_id);
            stmt.set_columns(columns.to_vec());
            stmt.set_executed(true);
            stmt.set_statement_type(crate::statement::StatementType::Query);

            let options = crate::messages::ExecuteOptions::for_ref_cursor(fetch_size);
            let mut execute_msg = ExecuteMessage::new(&stmt, options);
            execute_msg.set_sequence_number(0);
            execute_msg.build_request_with_sdu(&inner.capabilities, inner.large_sdu)?
        } else {
            let mut fetch_msg = FetchMessage::new(cursor_id, fetch_size);
            fetch_msg.set_sequence_number(inner.next_sequence_number());
            fetch_msg.build_request_with_sdu(&inner.capabilities, inner.large_sdu)?
        };

        if std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some() {
            eprintln!(
                "oracle-rs fetch request ({} bytes): {}",
                request.len(),
                hex::encode(request.as_ref())
            );
        }
        inner.send(&request).await?;

        // Receive and parse response (parse-driven termination: complete
        // exactly when the terminal Error/Status message has arrived)
        let response = self.receive_fetch_response(&mut inner, columns).await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty fetch response".to_string()));
        }
        if std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some() {
            eprintln!(
                "oracle-rs fetch response ({} bytes): {}",
                response.len(),
                hex::encode(response.as_ref())
            );
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            return self.parse_error_response(payload);
        }

        // Parse row data from response
        let payload = &response[PACKET_HEADER_SIZE..];
        let caps = inner.capabilities.clone();
        let legacy_11g = inner.server_info.protocol_version <= version::MIN_ACCEPTED;
        drop(inner); // Release lock before parsing
        let mut result = self.parse_fetch_response(
            payload,
            columns,
            &caps,
            cursor_id,
            previous_values.as_deref(),
        )?;
        if legacy_11g && !result.has_more_rows && result.rows.len() == fetch_size as usize {
            result.has_more_rows = true;
        }
        self.update_fetch_seed_row(result.cursor_id, &result.rows, result.has_more_rows, false)
            .await;
        Ok(result)
    }

    /// Fetch rows from a REF CURSOR
    ///
    /// This method fetches rows from a REF CURSOR that was returned from a
    /// PL/SQL procedure or function. The cursor contains the column metadata
    /// and cursor ID needed to fetch the rows.
    ///
    /// # Arguments
    ///
    /// * `cursor` - The REF CURSOR returned from PL/SQL
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::{Connection, BindParam, Value};
    ///
    /// // Call a procedure that returns a REF CURSOR
    /// let result = conn.execute_plsql(
    ///     "BEGIN OPEN :1 FOR SELECT id, name FROM employees; END;",
    ///     &[BindParam::output_cursor()]
    /// ).await?;
    ///
    /// // Get the cursor and fetch rows
    /// if let Value::Cursor(cursor) = &result.out_values[0] {
    ///     let rows = conn.fetch_cursor(cursor).await?;
    ///     println!("Fetched {} rows", rows.row_count());
    ///     for row in &rows.rows {
    ///         println!("{:?}", row);
    ///     }
    /// }
    /// ```
    pub async fn fetch_cursor(&self, cursor: &crate::types::RefCursor) -> Result<QueryResult> {
        self.fetch_cursor_with_size(cursor, 100).await
    }

    /// Fetch rows from a REF CURSOR with a specified fetch size
    ///
    /// This is the same as `fetch_cursor` but allows specifying how many
    /// rows to fetch at once.
    ///
    /// REF CURSORs use an ExecuteMessage with only the FETCH option because
    /// the cursor is already open from the PL/SQL execution. The cursor_id
    /// and column metadata were obtained when the REF CURSOR was returned.
    ///
    /// # Arguments
    ///
    /// * `cursor` - The REF CURSOR returned from PL/SQL
    /// * `fetch_size` - Number of rows to fetch (default is 100)
    pub async fn fetch_cursor_with_size(
        &self,
        cursor: &crate::types::RefCursor,
        fetch_size: u32,
    ) -> Result<QueryResult> {
        use crate::messages::ExecuteMessage;

        if cursor.cursor_id() == 0 {
            return Err(Error::InvalidCursor(
                "Cursor ID is 0 (not initialized)".to_string(),
            ));
        }

        self.ensure_ready().await?;

        // REF CURSOR uses ExecuteMessage with FETCH only (no SQL, no EXECUTE)
        // Create a statement with the cursor's metadata
        let mut stmt = Statement::new(""); // No SQL for REF CURSOR
        stmt.set_cursor_id(cursor.cursor_id());
        stmt.set_columns(cursor.columns().to_vec());
        stmt.set_executed(true); // Already executed by Oracle
        stmt.set_statement_type(crate::statement::StatementType::Query); // This is a query cursor

        // Build execute message with only FETCH option
        let options = crate::messages::ExecuteOptions::for_ref_cursor(fetch_size);
        let mut execute_msg = ExecuteMessage::new(&stmt, options);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let sequence_number = if inner.server_info.protocol_version <= version::MIN_ACCEPTED {
            0
        } else {
            inner.next_sequence_number()
        };
        execute_msg.set_sequence_number(sequence_number);

        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        if std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some() {
            eprintln!(
                "oracle-rs query request ({} bytes): {}",
                request.len(),
                hex::encode(request.as_ref())
            );
        }
        inner.send(&request).await?;

        // Receive and parse response (parse-driven termination: complete
        // exactly when the terminal Error/Status message has arrived)
        let response = self
            .receive_fetch_response(&mut inner, cursor.columns())
            .await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty cursor response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            return self.parse_error_response(payload);
        }

        // Parse query response - use cursor's columns since they're already defined
        let payload = &response[PACKET_HEADER_SIZE..];
        let caps = inner.capabilities.clone();
        let legacy_11g = inner.server_info.protocol_version <= version::MIN_ACCEPTED;
        let previous_values = inner.fetch_seed_rows.get(&cursor.cursor_id()).cloned();
        drop(inner); // Release lock before parsing
        let mut result = self.parse_fetch_response(
            payload,
            cursor.columns(),
            &caps,
            cursor.cursor_id(),
            previous_values.as_deref(),
        )?;
        if legacy_11g && !result.has_more_rows && result.rows.len() == fetch_size as usize {
            result.has_more_rows = true;
        }
        self.update_fetch_seed_row(result.cursor_id, &result.rows, result.has_more_rows, false)
            .await;
        Ok(result)
    }

    /// Fetch rows from an implicit result set
    ///
    /// Implicit results are returned via `DBMS_SQL.RETURN_RESULT` from PL/SQL.
    /// They contain cursor metadata but no rows until fetched.
    ///
    /// # Arguments
    ///
    /// * `result` - The implicit result from PL/SQL execution
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let plsql_result = conn.execute_plsql(r#"
    ///     declare
    ///         c sys_refcursor;
    ///     begin
    ///         open c for select * from employees;
    ///         dbms_sql.return_result(c);
    ///     end;
    /// "#, &[]).await?;
    ///
    /// for implicit in plsql_result.implicit_results.iter() {
    ///     let rows = conn.fetch_implicit_result(implicit).await?;
    ///     println!("Fetched {} rows", rows.row_count());
    /// }
    /// ```
    pub async fn fetch_implicit_result(&self, result: &ImplicitResult) -> Result<QueryResult> {
        self.fetch_implicit_result_with_size(result, 100).await
    }

    /// Fetch rows from an implicit result set with a specified fetch size
    pub async fn fetch_implicit_result_with_size(
        &self,
        result: &ImplicitResult,
        fetch_size: u32,
    ) -> Result<QueryResult> {
        // Convert implicit result to RefCursor and use fetch_cursor mechanism
        let cursor = crate::types::RefCursor::new(result.cursor_id, result.columns.clone());
        self.fetch_cursor_with_size(&cursor, fetch_size).await
    }

    /// Parse fetch response to extract additional rows
    ///
    /// REF CURSOR fetch responses contain a series of messages:
    /// - RowHeader (6): Contains metadata about the following row data
    /// - RowData (7): Contains the actual row values
    /// - Error (4): Contains error info with cursor_id and row counts
    fn parse_fetch_response(
        &self,
        payload: &[u8],
        columns: &[ColumnInfo],
        caps: &Capabilities,
        cursor_id: u16,
        previous_values_seed: Option<&[Value]>,
    ) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("Fetch response too short".to_string()));
        }

        let mut buf = ReadBuffer::from_slice(payload);
        let mut rows = Vec::new();
        let mut has_more_rows = false;
        let mut current_cursor_id = cursor_id;

        // Bit vector for duplicate column optimization
        let mut bit_vector: Option<Vec<u8>> = None;
        let mut previous_row_values = previous_values_seed.map(|values| values.to_vec());

        // Skip data flags
        buf.skip(2)?;

        // Process multiple messages in the response
        while buf.remaining() >= 1 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::RowHeader as u8 => {
                    // Skip row header metadata (per Python's _process_row_header)
                    buf.skip(1)?; // flags
                    buf.skip_ub2()?; // num requests
                    buf.skip_ub4()?; // iteration number
                    buf.skip_ub4()?; // num iters
                    buf.skip_ub2()?; // buffer length
                    let num_bytes = buf.read_ub4()?;
                    if num_bytes > 0 {
                        buf.skip(1)?; // skip repeated length
                                      // This bit vector in row header is for the following row data
                        let bv = buf.read_bytes_vec(num_bytes as usize)?;
                        bit_vector = Some(bv);
                    }
                    let rxhrid_bytes = buf.read_ub4()?;
                    if rxhrid_bytes > 0 {
                        buf.skip_raw_bytes_chunked()?;
                    }
                }
                x if x == MessageType::RowData as u8 => {
                    match self.parse_row_data_with_bitvector(
                        &mut buf,
                        columns,
                        caps,
                        bit_vector.as_deref(),
                        previous_row_values.as_ref(),
                    ) {
                        Ok(row) => {
                            previous_row_values = Some(row.values().to_vec());
                            bit_vector = None;
                            rows.push(row);
                        }
                        Err(Error::BufferUnderflow { .. }) => {
                            has_more_rows = true;
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }
                x if x == MessageType::BitVector as u8 => {
                    let _num_columns_sent = buf.read_ub2()?;
                    let num_bytes = (columns.len() + 7) / 8;
                    if num_bytes > 0 {
                        match buf.read_bytes_vec(num_bytes) {
                            Ok(bv) => bit_vector = Some(bv),
                            Err(Error::BufferUnderflow { .. }) => {
                                has_more_rows = true;
                                break;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
                x if x == MessageType::Error as u8 => {
                    // Error message contains row count and cursor info
                    let (error_code, error_msg, response_cursor_id, more_rows) =
                        self.parse_error_message_info(&mut buf, caps.ttc_field_version)?;
                    if response_cursor_id != 0 {
                        current_cursor_id = response_cursor_id;
                    }
                    has_more_rows = more_rows;
                    if error_code != 0 && error_code != 1403 {
                        // 1403 = no data found
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg,
                        });
                    }
                    break; // Error message marks end of response
                }
                x if x == MessageType::Status as u8 => {
                    // Status message - usually marks end
                    break;
                }
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }
                _ => {
                    // Unknown message type - stop processing
                    break;
                }
            }
        }

        Ok(QueryResult {
            columns: columns.to_vec(),
            rows,
            rows_affected: 0,
            has_more_rows,
            cursor_id: current_cursor_id,
        })
    }

    /// Parse error message info including cursor_id and row counts
    fn parse_error_message_info(
        &self,
        buf: &mut ReadBuffer,
        ttc_field_version: u8,
    ) -> Result<(u32, String, u16, bool)> {
        use crate::constants::ccap_value;

        let _call_status = buf.read_ub4()?; // end of call status
        buf.skip_ub2()?; // end to end seq#
        let current_row_number = buf.read_ub4()?;
        let error_num_short = buf.read_ub2()? as u32;
        buf.skip_ub2()?; // array elem error
        buf.skip_ub2()?; // array elem error
        let cursor_id = buf.read_ub2()?; // cursor id
        let _error_pos = buf.read_sb2()?; // error position
        buf.skip_ub1()?; // sql type
        buf.skip_ub1()?; // fatal?
        buf.skip_ub1()?; // flags
        buf.skip_ub1()?; // user cursor options
        buf.skip_ub1()?; // UPI parameter
        let flags = buf.read_u8()?; // flags
                                    // Rowid (rba, partition_id, skip 1, block_num, slot_num)
        buf.skip_ub4()?;
        buf.skip_ub2()?;
        buf.skip_ub1()?;
        buf.skip_ub4()?;
        buf.skip_ub2()?;
        buf.skip_ub4()?; // OS error
        buf.skip_ub1()?; // statement number
        buf.skip_ub1()?; // call number
        buf.skip_ub2()?; // padding
        buf.skip_ub4()?; // success iters
        let num_bytes = buf.read_ub4()?; // oerrdd
        if num_bytes > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Skip batch error codes
        let num_errors = buf.read_ub2()?;
        if num_errors > 0 {
            buf.skip_ub1()?;
            for _ in 0..num_errors {
                buf.skip_ub2()?;
            }
        }

        // Skip batch error offsets
        let num_offsets = buf.read_ub4()?;
        if num_offsets > 0 {
            buf.skip_ub1()?;
            for _ in 0..num_offsets {
                buf.skip_ub4()?;
            }
        }

        // Skip batch error messages
        let temp16 = buf.read_ub2()?;
        if temp16 > 0 {
            buf.skip_ub1()?;
            for _ in 0..temp16 {
                buf.skip_ub2()?;
                buf.read_string_with_length()?;
                buf.skip(2)?;
            }
        }

        let (error_num, row_count, read_extended_info) = self.read_optional_extended_error_info(
            buf,
            error_num_short,
            current_row_number as u64,
        )?;

        // sql_type + server_checksum were added in Oracle 20c; python-oracledb
        // gates them on TNS_CCAP_FIELD_VERSION_20_1 (14).
        if ttc_field_version >= ccap_value::FIELD_VERSION_20_1 && read_extended_info {
            buf.skip_ub4()?; // sql_type
            buf.skip_ub4()?; // server_checksum
        }

        let more_rows = error_num == 0 && (row_count > 0 || (flags & 0x20) != 0);
        let error_msg = self
            .read_optional_error_message(buf, error_num)?
            .unwrap_or_default();

        Ok((error_num, error_msg, cursor_id, more_rows))
    }

    /// Open a scrollable cursor for bidirectional navigation
    ///
    /// Scrollable cursors allow moving forward and backward through result sets,
    /// jumping to specific positions, and fetching from various locations.
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL query to execute
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut cursor = conn.open_scrollable_cursor("SELECT * FROM employees").await?;
    ///
    /// // Move to different positions
    /// let first = conn.scroll(&mut cursor, FetchOrientation::First, 0).await?;
    /// let last = conn.scroll(&mut cursor, FetchOrientation::Last, 0).await?;
    /// let row5 = conn.scroll(&mut cursor, FetchOrientation::Absolute, 5).await?;
    ///
    /// conn.close_cursor(&mut cursor).await?;
    /// ```
    pub async fn open_scrollable_cursor(&self, sql: &str) -> Result<ScrollableCursor> {
        self.ensure_ready().await?;

        let statement = Statement::new(sql);

        // For scrollable cursors, execute with scrollable flag and prefetch 1 row
        // to get column metadata. The scroll() method will fetch actual rows at
        // specific positions.
        let mut options = ExecuteOptions::for_query(1); // prefetch 1 row for column info

        options.scrollable = true;

        let mut execute_msg = ExecuteMessage::new(&statement, options);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;

        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol(
                "Empty scrollable cursor response".to_string(),
            ));
        }

        // Check for MARKER packet (indicates error - requires reset protocol)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Handle marker reset protocol and get the error packet
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            // Parse error response to extract the actual Oracle error
            let _: QueryResult = self.parse_error_response(payload)?;
            // If we get here without error, something unexpected happened
            return Err(Error::Protocol(
                "Unexpected successful response after MARKER".to_string(),
            ));
        }

        // Parse describe info to get columns
        let payload = &response[PACKET_HEADER_SIZE..];
        let result = self.parse_query_response(payload, &inner.capabilities)?;

        Ok(ScrollableCursor::new(result.cursor_id, result.columns))
    }

    /// Scroll to a position in a scrollable cursor and fetch rows
    ///
    /// # Arguments
    ///
    /// * `cursor` - The scrollable cursor to scroll
    /// * `orientation` - The direction/mode of scrolling
    /// * `offset` - Position offset (used for Absolute and Relative modes)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Go to first row
    /// let first = conn.scroll(&mut cursor, FetchOrientation::First, 0).await?;
    ///
    /// // Go to absolute position 10
    /// let row10 = conn.scroll(&mut cursor, FetchOrientation::Absolute, 10).await?;
    ///
    /// // Move 5 rows forward from current position
    /// let plus5 = conn.scroll(&mut cursor, FetchOrientation::Relative, 5).await?;
    ///
    /// // Move 3 rows backward
    /// let minus3 = conn.scroll(&mut cursor, FetchOrientation::Relative, -3).await?;
    /// ```
    pub async fn scroll(
        &self,
        cursor: &mut ScrollableCursor,
        orientation: FetchOrientation,
        offset: i64,
    ) -> Result<ScrollResult> {
        self.ensure_ready().await?;

        if !cursor.is_open() {
            return Err(Error::CursorClosed);
        }

        // Create a statement for the scroll operation (uses the existing cursor)
        let mut stmt = Statement::new("");
        stmt.set_cursor_id(cursor.cursor_id);
        stmt.set_columns(cursor.columns.clone());
        stmt.set_executed(true);
        stmt.set_statement_type(crate::statement::StatementType::Query);

        // Build execute message with scroll_operation=true
        let mut options = ExecuteOptions::for_query(1);
        options.scrollable = true;
        options.scroll_operation = true;
        options.fetch_orientation = orientation as u32;
        // Calculate fetch_pos based on orientation
        options.fetch_pos = match orientation {
            FetchOrientation::First => 1,
            FetchOrientation::Last => 0, // Server calculates
            FetchOrientation::Absolute => offset.max(0) as u32,
            FetchOrientation::Relative => (cursor.position + offset).max(0) as u32,
            FetchOrientation::Next => (cursor.position + 1).max(0) as u32,
            FetchOrientation::Prior => (cursor.position - 1).max(0) as u32,
            FetchOrientation::Current => cursor.position.max(0) as u32,
        };

        let mut execute_msg = ExecuteMessage::new(&stmt, options);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty scroll response".to_string()));
        }

        // Check for MARKER packet
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let _: QueryResult = self.parse_error_response(payload)?;
            return Err(Error::Protocol("Scroll operation failed".to_string()));
        }

        let payload = &response[PACKET_HEADER_SIZE..];
        // Use cursor's columns since Oracle doesn't re-send column metadata for scroll operations
        let query_result =
            self.parse_query_response_with_columns(payload, &inner.capabilities, &cursor.columns)?;

        // Use position from Oracle's response (rows_affected contains the row position)
        // For scrollable cursors, Oracle returns the row number in error_info.rowcount
        let new_position = if !query_result.rows.is_empty() {
            // Position is the actual row number from Oracle
            query_result.rows_affected as i64
        } else {
            // No rows returned - calculate position based on orientation
            match orientation {
                FetchOrientation::First => 0, // Before first
                FetchOrientation::Last => cursor.row_count.unwrap_or(0) as i64 + 1, // After last
                FetchOrientation::Next => cursor.position + 1,
                FetchOrientation::Prior => cursor.position - 1,
                FetchOrientation::Absolute => offset,
                FetchOrientation::Relative => cursor.position + offset,
                FetchOrientation::Current => cursor.position,
            }
        };

        cursor.update_position(new_position);

        let mut result = ScrollResult::new(query_result.rows, new_position);
        result.at_end = !query_result.has_more_rows;
        result.at_beginning = new_position <= 1;

        Ok(result)
    }

    /// Close a scrollable cursor
    ///
    /// # Arguments
    ///
    /// * `cursor` - The scrollable cursor to close
    pub async fn close_cursor(&self, cursor: &mut ScrollableCursor) -> Result<()> {
        if !cursor.is_open() {
            return Ok(());
        }

        // Drop any BitVector decompression seed held for this cursor id so it
        // cannot be served to a later fetch on a reused cursor id.
        {
            let mut inner = self.inner.lock().await;
            inner.fetch_seed_rows.remove(&cursor.cursor_id());
        }

        // Send close cursor message
        // For now, just mark it as closed - the cursor will be cleaned up
        // when the connection is closed or reused
        cursor.mark_closed();
        Ok(())
    }

    /// Get type information for a database object or collection type
    ///
    /// This method queries Oracle's data dictionary to retrieve type metadata
    /// for collections (VARRAY, Nested Table) and user-defined object types.
    ///
    /// # Arguments
    ///
    /// * `type_name` - Fully qualified type name (e.g., "SCHEMA.TYPE_NAME" or just "TYPE_NAME")
    ///
    /// # Returns
    ///
    /// A `DbObjectType` containing the type metadata, including:
    /// - Schema and type name
    /// - Whether it's a collection
    /// - Collection type (VARRAY, Nested Table, etc.)
    /// - Element type for collections
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let number_array = conn.get_type("MY_NUMBER_ARRAY").await?;
    /// assert!(number_array.is_collection);
    /// ```
    pub async fn get_type(&self, type_name: &str) -> Result<crate::dbobject::DbObjectType> {
        use crate::dbobject::{CollectionType, DbObjectType};

        self.ensure_ready().await?;

        // Parse type name into schema and name
        let (schema, name) = parse_type_name(type_name, &self.config.username);

        // First, query ALL_TYPES to get basic type info
        let type_info = self
            .query(
                "SELECT typecode, type_oid FROM all_types WHERE owner = :1 AND type_name = :2",
                &[Value::String(schema.clone()), Value::String(name.clone())],
            )
            .await?;

        if type_info.rows.is_empty() {
            return Err(Error::OracleError {
                code: 4043, // ORA-04043: object does not exist
                message: format!("Type {}.{} not found", schema, name),
            });
        }

        let row = &type_info.rows[0];
        let typecode = row.get(0).and_then(|v| v.as_str()).unwrap_or("");
        let type_oid = row.get(1).and_then(|v| v.as_bytes()).map(|b| b.to_vec());

        // Check if it's a collection
        if typecode == "COLLECTION" {
            // Query ALL_COLL_TYPES for collection details
            let coll_info = self.query(
                "SELECT coll_type, elem_type_name, elem_type_owner, upper_bound FROM all_coll_types WHERE owner = :1 AND type_name = :2",
                &[Value::String(schema.clone()), Value::String(name.clone())],
            ).await?;

            if coll_info.rows.is_empty() {
                return Err(Error::OracleError {
                    code: 4043,
                    message: format!("Collection type {}.{} metadata not found", schema, name),
                });
            }

            let coll_row = &coll_info.rows[0];
            let coll_type_str = coll_row.get(0).and_then(|v| v.as_str()).unwrap_or("");
            let elem_type_name = coll_row
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("VARCHAR2");
            let _elem_type_owner = coll_row.get(2).and_then(|v| v.as_str());

            let collection_type = match coll_type_str {
                "VARYING ARRAY" => CollectionType::Varray,
                "TABLE" => CollectionType::NestedTable,
                _ => CollectionType::Varray, // Default
            };

            let element_type = oracle_type_from_name(elem_type_name);

            let mut obj_type =
                DbObjectType::collection(schema, name, collection_type, element_type);
            obj_type.oid = type_oid;
            Ok(obj_type)
        } else {
            // Regular object type (not yet fully implemented)
            let mut obj_type = DbObjectType::new(schema, name);
            obj_type.oid = type_oid;
            Ok(obj_type)
        }
    }

    /// Internal: Execute a query statement with optional bind parameters
    async fn execute_query_with_params(
        &self,
        statement: &Statement,
        params: &[Value],
    ) -> Result<QueryResult> {
        // Oracle 11g (TNS 314) does not set END_OF_RESPONSE flags in data
        // packets, so receive_response() cannot detect the end of a
        // multi-packet result set.  Use prefetch_rows=0 for 11g so the
        // execute returns only describe info + cursor; rows are then
        // fetched in batches via fetch_more().
        let protocol_version = {
            let inner = self.inner.lock().await;
            inner.server_info.protocol_version
        };
        // 11g cannot detect multi-packet end-of-response, so it defaults to no
        // prefetch (rows fetched via fetch_more()); newer servers prefetch 100.
        let default_prefetch_rows: u32 = if protocol_version <= version::MIN_ACCEPTED {
            0
        } else {
            100
        };
        let prefetch_rows: u32 = std::env::var("ORACLE_RS_PREFETCH_ROWS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_prefetch_rows);

        let options = ExecuteOptions::for_query(prefetch_rows);
        let mut execute_msg = ExecuteMessage::new(statement, options);

        // Set bind values if provided
        if !params.is_empty() {
            execute_msg.set_bind_values(params.to_vec());
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let sequence_number = if inner.server_info.protocol_version <= version::MIN_ACCEPTED {
            0
        } else {
            inner.next_sequence_number()
        };
        execute_msg.set_sequence_number(sequence_number);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        if std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some() {
            eprintln!(
                "oracle-rs query request ({} bytes): {}",
                request.len(),
                hex::encode(request.as_ref())
            );
        }
        inner.send(&request).await?;

        // Receive response — accumulate all packets.
        // For Oracle 11g, receive_response() uses terminal message scanning
        // to detect end of response since END_OF_RESPONSE flags are absent.
        let response = inner.receive_response().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty query response".to_string()));
        }

        if std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some() {
            eprintln!(
                "oracle-rs query response ({} bytes): {}",
                response.len(),
                hex::encode(response.as_ref())
            );
        }

        // Check for MARKER packet (indicates error - requires reset protocol)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Handle marker reset protocol and get the error packet
            let error_response = inner.handle_marker_reset().await?;
            if std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some() {
                eprintln!(
                    "oracle-rs query error response ({} bytes): {}",
                    error_response.len(),
                    hex::encode(error_response.as_ref())
                );
            }
            let payload = &error_response[PACKET_HEADER_SIZE..];
            return self.parse_error_response(payload);
        }

        // Parse the response to extract columns and rows
        let payload = &response[PACKET_HEADER_SIZE..];
        let mut result = self.parse_query_response(payload, &inner.capabilities)?;

        // Check if any columns are LOB types that require defines
        let has_lob_columns = result.columns.iter().any(|col| col.is_lob());

        if has_lob_columns && !statement.requires_define() {
            // We need to re-execute with column defines
            // Create a modified statement with the define flag set
            let mut stmt_with_define = statement.clone();
            stmt_with_define.set_columns(result.columns.clone());
            stmt_with_define.set_cursor_id(result.cursor_id);
            stmt_with_define.set_requires_define(true);
            stmt_with_define.set_no_prefetch(true);
            stmt_with_define.set_executed(true);

            // Re-execute with defines
            let define_options = ExecuteOptions::for_query(prefetch_rows);
            let mut define_msg = ExecuteMessage::new(&stmt_with_define, define_options);
            let seq_num = inner.next_sequence_number();
            define_msg.set_sequence_number(seq_num);

            let define_request =
                define_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
            inner.send(&define_request).await?;

            // Receive the re-execute response. LOB define responses can span
            // packets when the locator/prefetch data is near the SDU boundary.
            let define_response = inner.receive_response().await?;
            if define_response.len() <= PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Empty define response".to_string()));
            }

            // Check for MARKER packet
            let packet_type = define_response[4];
            if packet_type == PacketType::Marker as u8 {
                let error_response = inner.handle_marker_reset().await?;
                if std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some() {
                    eprintln!(
                        "oracle-rs query define error response ({} bytes): {}",
                        error_response.len(),
                        hex::encode(error_response.as_ref())
                    );
                }
                let payload = &error_response[PACKET_HEADER_SIZE..];
                return self.parse_error_response(payload);
            }

            // Parse the response with LOB data, using the columns we already know
            let payload = &define_response[PACKET_HEADER_SIZE..];
            result = self.parse_query_response_with_columns(
                payload,
                &inner.capabilities,
                stmt_with_define.columns(),
            )?;
        }

        Ok(result)
    }

    /// Internal: Execute a DML statement with optional bind parameters
    async fn execute_dml_with_params(
        &self,
        statement: &Statement,
        params: &[Value],
    ) -> Result<QueryResult> {
        let options = ExecuteOptions::for_dml(false); // Don't auto-commit
        let mut execute_msg = ExecuteMessage::new(statement, options);

        // Set bind values if provided
        if !params.is_empty() {
            execute_msg.set_bind_values(params.to_vec());
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;

        inner.send(&request).await?;

        // Receive response
        let mut response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty DML response".to_string()));
        }

        // Check packet type - handle MARKER packets
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Need to do reset protocol and then get the actual response
            // Extract marker type from packet: after header (8 bytes) + data flags (2 bytes) + marker type (1 byte)
            let marker_type = if response.len() >= PACKET_HEADER_SIZE + 3 {
                response[PACKET_HEADER_SIZE + 2]
            } else {
                1 // Assume BREAK
            };

            if marker_type == 1 {
                // BREAK marker - send RESET and wait for response
                self.send_marker(&mut inner, 2).await?;

                // Wait for RESET marker back or DATA packet with error
                // The server may send: RESET marker, or BREAK marker followed by DATA, or just close
                let mut got_reset = false;
                let mut max_attempts = 5;
                loop {
                    match inner.receive().await {
                        Ok(pkt) => {
                            if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                break;
                            }
                            let pkt_type = pkt[4];
                            if pkt_type == PacketType::Marker as u8 {
                                if pkt.len() >= PACKET_HEADER_SIZE + 3 {
                                    let mk_type = pkt[PACKET_HEADER_SIZE + 2];
                                    if mk_type == 2 {
                                        // Got RESET marker, break out
                                        got_reset = true;
                                        break;
                                    }
                                    // Got another BREAK marker - server may be acknowledging
                                    // Keep trying a few times
                                    max_attempts -= 1;
                                    if max_attempts == 0 {
                                        // Give up and return a generic error
                                        return Err(Error::Protocol(
                                            "Server rejected operation (multiple BREAK markers)"
                                                .to_string(),
                                        ));
                                    }
                                    continue;
                                }
                            } else if pkt_type == PacketType::Data as u8 {
                                // Got DATA packet - use this as the response (may contain error)
                                let payload = &pkt[PACKET_HEADER_SIZE..];
                                return self.parse_dml_response(
                                    payload,
                                    inner.capabilities.ttc_field_version,
                                );
                            } else {
                                break;
                            }
                        }
                        Err(e) => {
                            // If we get EOF, the server may have closed the connection
                            // This can happen with temp LOB binding issues
                            inner.state = ConnectionState::Closed;
                            return Err(Error::Protocol(format!(
                                "Server closed connection during error handling: {}",
                                e
                            )));
                        }
                    }
                }

                // After RESET, try to receive DATA packet with error response
                // Note: Some Oracle servers "quit immediately" after reset without sending
                // an error packet. In that case, we'll get EOF which is handled below.
                if got_reset {
                    loop {
                        match inner.receive().await {
                            Ok(pkt) => {
                                if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                    // Too short, connection may be closing
                                    break;
                                }
                                let pkt_type = pkt[4];
                                if pkt_type == PacketType::Marker as u8 {
                                    // More markers, keep reading
                                    continue;
                                } else if pkt_type == PacketType::Data as u8 {
                                    // Got DATA packet, use this as the response
                                    response = pkt;
                                    break;
                                } else {
                                    // Unknown packet type, return error
                                    return Err(Error::Protocol(format!(
                                        "Unexpected packet type {} after reset",
                                        pkt_type
                                    )));
                                }
                            }
                            Err(_e) => {
                                // EOF after reset is normal - server may close connection
                                // without sending error details. Return a descriptive error.
                                inner.state = ConnectionState::Closed;
                                return Err(Error::OracleError {
                                    code: 0,
                                    message: "Server rejected the operation and closed the connection. \
                                              This may happen when binding a temporary LOB to an INSERT statement. \
                                              Try using a different approach (e.g., DBMS_LOB procedures).".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Parse the response to extract rows affected (or error)
        let payload = &response[PACKET_HEADER_SIZE..];
        self.parse_dml_response(payload, inner.capabilities.ttc_field_version)
    }

    /// Parse query response to extract columns and rows
    ///
    /// Oracle sends multiple messages in a single response:
    /// - DescribeInfo (16): column metadata
    /// - RowHeader (6): row header info
    /// - RowData (7): actual column values
    /// - Error (4): completion status (may contain error or success)
    fn parse_query_response(&self, payload: &[u8], caps: &Capabilities) -> Result<QueryResult> {
        self.parse_query_response_with_columns(payload, caps, &[])
    }

    fn is_query_response_message_type(msg_type: u8) -> bool {
        matches!(
            msg_type,
            x if x == MessageType::RowHeader as u8
                || x == MessageType::RowData as u8
                || x == MessageType::Error as u8
                || x == MessageType::Parameter as u8
                || x == MessageType::Status as u8
                || x == MessageType::BitVector as u8
                || x == MessageType::EndOfResponse as u8
        )
    }

    fn read_u16_be_at(data: &[u8], pos: usize) -> Option<u16> {
        let bytes = data.get(pos..pos + 2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32_legacy_at(data: &[u8], pos: usize, max_value: u32) -> Option<u32> {
        let bytes = data.get(pos..pos + 4)?;
        let be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if be <= max_value {
            return Some(be);
        }

        let le = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if le <= max_value {
            Some(le)
        } else {
            None
        }
    }

    fn skip_legacy_11g_raw(data: &[u8], pos: usize, len: usize) -> Option<usize> {
        if len == 0 {
            return Some(pos);
        }

        if data.get(pos).copied() == Some(len as u8) && pos + 1 + len <= data.len() {
            Some(pos + 1 + len)
        } else if pos + len <= data.len() {
            Some(pos + len)
        } else {
            None
        }
    }

    fn try_parse_legacy_11g_describe_at(
        &self,
        data: &[u8],
        pos: usize,
        num_columns: usize,
    ) -> Option<(Vec<ColumnInfo>, usize)> {
        if !(1..=1024).contains(&num_columns) {
            return None;
        }

        let mut p = pos + 8;
        let mut columns = Vec::with_capacity(num_columns);

        for _ in 0..num_columns {
            let ora_type_num = *data.get(p)?;
            let precision = *data.get(p + 2)? as i8 as i16;
            let scale = *data.get(p + 3)? as i8 as i16;
            p += 4;

            let buffer_size = Self::read_u32_legacy_at(data, p, 1_000_000)?;
            p += 4;
            p += 4; // max_num_array_elements
            p += 8; // cont_flags

            let oid_length = Self::read_u32_legacy_at(data, p, data.len() as u32)? as usize;
            p += 4;
            p = p.checked_add(oid_length)?;
            data.get(p)?;

            p += 2; // version
            p += 2; // charset_id
            let csfrm = *data.get(p)?;
            p += 1;

            let max_size = *data.get(p)? as u32;
            p += 1;
            let nullable = *data.get(p)? != 0;
            p += 1;
            p += 1; // v7 length of name

            let name_len = Self::read_u32_legacy_at(data, p, data.len() as u32)? as usize;
            p += 4;
            let name_bytes = data.get(p..p + name_len)?;
            let name = String::from_utf8_lossy(name_bytes).to_string();
            p += name_len;

            let schema_len = Self::read_u32_legacy_at(data, p, data.len() as u32)? as usize;
            p += 4 + schema_len;
            data.get(p)?;

            let type_name_len = Self::read_u32_legacy_at(data, p, data.len() as u32)? as usize;
            p += 4 + type_name_len;
            data.get(p)?;

            let _position = Self::read_u16_be_at(data, p)?;
            p += 2;
            p += 4; // uds_flags

            let oracle_type = OracleType::try_from(ora_type_num).unwrap_or(OracleType::Varchar);
            let mut col = ColumnInfo::new(name, oracle_type);
            col.buffer_size = buffer_size;
            col.data_size = if max_size > 0 { max_size } else { buffer_size };
            col.precision = precision;
            col.scale = scale;
            col.nullable = nullable;
            col.csfrm = csfrm;
            columns.push(col);
        }

        let current_date_len = Self::read_u32_legacy_at(data, p, data.len() as u32)? as usize;
        p += 4;
        p = Self::skip_legacy_11g_raw(data, p, current_date_len)?;

        p += 16; // dcbflag, dcbmdbz, dcbmnpr, dcbmxpr
        let qcky_len = Self::read_u32_legacy_at(data, p, data.len() as u32)? as usize;
        p += 4;
        p = Self::skip_legacy_11g_raw(data, p, qcky_len)?;

        Some((columns, p))
    }

    fn parse_legacy_11g_describe_info(
        &self,
        buf: &mut ReadBuffer,
        describe_start: usize,
    ) -> Result<Option<Vec<ColumnInfo>>> {
        let data = buf.as_bytes();
        let bytes = data.as_ref();

        for pos in describe_start..bytes.len().saturating_sub(8) {
            let Some(num_columns) = Self::read_u32_legacy_at(bytes, pos, 1024) else {
                continue;
            };
            let Some(max_row_size) = Self::read_u32_legacy_at(bytes, pos + 4, 1_000_000) else {
                continue;
            };
            if num_columns == 0 || num_columns > 1024 || max_row_size > 1_000_000 {
                continue;
            }

            let Some((columns, end_pos)) =
                self.try_parse_legacy_11g_describe_at(bytes, pos, num_columns as usize)
            else {
                continue;
            };
            if columns.is_empty()
                || !bytes
                    .get(end_pos)
                    .copied()
                    .is_some_and(Self::is_query_response_message_type)
            {
                continue;
            }

            buf.set_position(end_pos)?;
            return Ok(Some(columns));
        }

        Ok(None)
    }

    fn skip_legacy_11g_row_header(&self, buf: &mut ReadBuffer) -> Result<()> {
        let start = buf.position();
        let remaining = buf.remaining_slice();

        for (skip, &byte) in remaining.iter().enumerate() {
            if byte == MessageType::RowData as u8
                || byte == MessageType::Error as u8
                || byte == MessageType::BitVector as u8
            {
                buf.set_position(start + skip)?;
                return Ok(());
            }
        }

        Err(Error::Protocol(
            "Unable to skip Oracle 11g row header".to_string(),
        ))
    }

    fn skip_legacy_11g_parameter(&self, buf: &mut ReadBuffer) -> Result<()> {
        let start = buf.position();
        let remaining = buf.remaining_slice();

        for (skip, &byte) in remaining.iter().enumerate() {
            if byte == MessageType::Error as u8
                || byte == MessageType::Status as u8
                || byte == MessageType::EndOfResponse as u8
            {
                buf.set_position(start + skip)?;
                return Ok(());
            }
        }

        Err(Error::Protocol(
            "Unable to skip Oracle 11g parameter message".to_string(),
        ))
    }

    fn parse_query_describe_info(
        &self,
        buf: &mut ReadBuffer,
        caps: &Capabilities,
    ) -> Result<(Vec<ColumnInfo>, Option<Vec<u8>>)> {
        // The describe info response starts with a TNS chunked-encoded
        // prefix (current date, dcb flags, etc.) followed by the column
        // metadata.  On Oracle 12c+ the chunked prefix is small and
        // skip_raw_bytes_chunked works.  On Oracle 11g the **entire**
        // response (including column metadata, row data, and the error
        // trailer) is delivered inside a single chunked stream.
        //
        // Strategy: read the chunked prefix.  If the next byte after the
        // prefix is a valid query-response message type we are done.
        // Otherwise de-chunk the remaining data and re-parse from the
        // de-chunked buffer.

        let describe_start = buf.position();

        // Try the 12c+ path first: skip the chunked prefix, then parse
        // describe info directly from the remaining buffer.
        buf.skip_raw_bytes_chunked()?;
        let after_prefix = buf.position();
        let columns = self.parse_describe_info(buf, caps.ttc_field_version)?;
        if !columns.is_empty()
            && (caps.is_legacy_11g_ttc()
                || buf
                    .remaining_slice()
                    .first()
                    .copied()
                    .is_some_and(Self::is_query_response_message_type))
        {
            return Ok((columns, None));
        }

        // 11g fallback: some captures place a short chunked prelude ahead of
        // the actual describe metadata. Scan the remaining outer buffer for a
        // valid describe-info block and advance the original cursor to the end
        // of the parsed metadata when found.
        buf.set_position(after_prefix)?;
        let remaining = buf.remaining_slice();
        let ttc_ver = caps.ttc_field_version;
        for skip in 0..remaining.len().saturating_sub(4) {
            let mut probe = ReadBuffer::from_slice(&remaining[skip..]);
            let Ok(cols) = self.parse_describe_info(&mut probe, ttc_ver) else {
                continue;
            };
            if cols.is_empty()
                || !probe
                    .remaining_slice()
                    .first()
                    .copied()
                    .is_some_and(Self::is_query_response_message_type)
            {
                continue;
            }
            buf.set_position(after_prefix + skip + probe.position())?;
            return Ok((cols, None));
        }

        if caps.is_legacy_11g_ttc() {
            if let Some(cols) = self.parse_legacy_11g_describe_info(buf, describe_start)? {
                return Ok((cols, None));
            }
        }

        // Final fallback: re-read from the original position and de-chunk the
        // prefix bytes themselves for older captures where the metadata really
        // is nested inside a chunked blob.
        buf.set_position(describe_start)?;
        let dechunked = buf.read_raw_bytes_chunked()?;
        if std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some() {
            eprintln!(
                "oracle-rs 11g dechunked describe ({} bytes), outer remaining={}",
                dechunked.len(),
                buf.remaining(),
            );
        }
        if dechunked.is_empty() {
            return Ok((Vec::new(), None));
        }

        let outer_remaining = buf.remaining_slice().to_vec();
        for skip in 0..dechunked.len().saturating_sub(4) {
            let mut probe = ReadBuffer::from_slice(&dechunked[skip..]);
            let Ok(cols) = self.parse_describe_info(&mut probe, ttc_ver) else {
                continue;
            };
            if cols.is_empty()
                || !probe
                    .remaining_slice()
                    .first()
                    .copied()
                    .is_some_and(Self::is_query_response_message_type)
            {
                continue;
            }
            let mut inline_tail = probe.remaining_slice().to_vec();
            inline_tail.extend_from_slice(&outer_remaining);
            return Ok((cols, Some(inline_tail)));
        }

        Err(Error::Protocol(
            "Unable to parse Oracle 11g describe info from de-chunked payload".to_string(),
        ))
    }

    /// Parse query response with pre-known columns (for re-execute after define)
    fn parse_query_response_with_columns(
        &self,
        payload: &[u8],
        caps: &Capabilities,
        known_columns: &[ColumnInfo],
    ) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("Query response too short".to_string()));
        }

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        // Use known columns if provided, otherwise parse from describe info
        let mut columns: Vec<ColumnInfo> = known_columns.to_vec();
        let mut rows: Vec<Row> = Vec::new();
        let mut cursor_id: u16 = 0;
        let mut row_count: u64 = 0;
        let mut end_of_response = false;

        // Bit vector for duplicate column optimization
        // When Some, indicates which columns have actual data (bit=1) vs duplicates (bit=0)
        let mut bit_vector: Option<Vec<u8>> = None;
        // Previous row values for copying duplicates
        let mut previous_row_values: Option<Vec<Value>> = None;

        // Hoisted once instead of re-reading the environment on every message.
        let debug = std::env::var_os("ORACLE_RS_DEBUG_QUERY").is_some();

        // Process messages until we hit end of response or run out of data.
        // On Oracle 11g a single TNS packet may not contain all rows; when
        // we hit a BufferUnderflow while parsing row data we return what we
        // have so far with has_more_rows = true so the caller can use
        // fetch_more().
        while !end_of_response && buf.remaining() > 0 {
            let msg_pos = buf.position();
            let msg_type = buf.read_u8()?;

            if debug {
                eprintln!(
                    "oracle-rs query msg_type={} payload_offset={} remaining={}",
                    msg_type,
                    msg_pos,
                    buf.remaining()
                );
            }

            match msg_type {
                // DescribeInfo (16) - column metadata
                x if x == MessageType::DescribeInfo as u8 => {
                    let (parsed_columns, inline_tail) =
                        self.parse_query_describe_info(&mut buf, caps)?;
                    columns = parsed_columns;
                    if let Some(inline_tail) = inline_tail {
                        buf = ReadBuffer::from_vec(inline_tail);
                    }
                }

                // RowHeader (6) - header info for rows
                x if x == MessageType::RowHeader as u8 => {
                    let row_header_start = buf.position();
                    match self.parse_row_header(&mut buf) {
                        Ok(()) => {
                            if caps.ttc_field_version
                                <= crate::constants::ccap_value::FIELD_VERSION_11_2
                                && !buf
                                    .remaining_slice()
                                    .first()
                                    .copied()
                                    .is_some_and(Self::is_query_response_message_type)
                            {
                                buf.set_position(row_header_start)?;
                                self.skip_legacy_11g_row_header(&mut buf)?;
                            }
                        }
                        Err(Error::BufferUnderflow { .. })
                            if caps.ttc_field_version
                                <= crate::constants::ccap_value::FIELD_VERSION_11_2 =>
                        {
                            buf.set_position(row_header_start)?;
                            self.skip_legacy_11g_row_header(&mut buf)?;
                        }
                        Err(Error::BufferUnderflow { .. }) => break,
                        Err(e) => return Err(e),
                    }
                }

                // RowData (7) - actual row values
                x if x == MessageType::RowData as u8 => {
                    match self.parse_row_data_with_bitvector(
                        &mut buf,
                        &columns,
                        caps,
                        bit_vector.as_deref(),
                        previous_row_values.as_ref(),
                    ) {
                        Ok(row) => {
                            previous_row_values = Some(row.values().to_vec());
                            bit_vector = None;
                            rows.push(row);
                        }
                        Err(Error::BufferUnderflow { .. }) => {
                            // Partial packet — return rows parsed so far
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }

                // Error (4) - completion or error
                x if x == MessageType::Error as u8 => {
                    let parsed_error =
                        self.parse_error_info_with_rowcount(&mut buf, caps.ttc_field_version);
                    let (error_code, error_msg, cid, rc) = match parsed_error {
                        Ok(parsed) => parsed,
                        Err(Error::BufferUnderflow { .. } | Error::InvalidLengthIndicator(_))
                            if caps.is_legacy_11g_ttc() && !rows.is_empty() =>
                        {
                            end_of_response = true;
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    cursor_id = cid;
                    row_count = rc;
                    if error_code != 0 && error_code != 1403 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                    // error_code=1403 means "no data found" = truly done.
                    // error_code=0 means success; if rows < prefetch count,
                    // there may be more rows to fetch.
                    end_of_response = error_code == 1403;
                }

                // Parameter (8) - return parameters
                x if x == MessageType::Parameter as u8 => {
                    let parameter_start = buf.position();
                    match self.parse_return_parameters(&mut buf) {
                        Ok(()) => {}
                        Err(Error::BufferUnderflow { .. } | Error::InvalidLengthIndicator(_))
                            if caps.is_legacy_11g_ttc() =>
                        {
                            buf.set_position(parameter_start)?;
                            self.skip_legacy_11g_parameter(&mut buf)?;
                        }
                        Err(Error::BufferUnderflow { .. }) => break,
                        Err(e) => return Err(e),
                    }
                }

                // Status (9) - call status
                x if x == MessageType::Status as u8 => {
                    // Read call status and end-to-end seq number
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                }

                // BitVector (21) - column presence bitmap for sparse results
                // Bit=1 means actual data is sent, bit=0 means duplicate from previous row
                21 => {
                    let num_cols_sent = buf.read_ub2()?;
                    let _ = num_cols_sent;
                    let num_bytes = (columns.len() + 7) / 8;
                    if num_bytes > 0 {
                        match buf.read_bytes_vec(num_bytes) {
                            Ok(bv) => bit_vector = Some(bv),
                            Err(Error::BufferUnderflow { .. }) => break,
                            Err(e) => return Err(e),
                        }
                    }
                }

                _ => {
                    break;
                }
            }
        }

        Ok(QueryResult {
            columns,
            rows,
            rows_affected: row_count,
            has_more_rows: !end_of_response && cursor_id > 0,
            cursor_id,
        })
    }

    /// Parse a PL/SQL response containing OUT parameter values
    ///
    /// PL/SQL responses may contain:
    /// - IoVector (11): bind directions for each parameter
    /// - RowData (7): OUT parameter values
    /// - FlushOutBinds (19): signals end of OUT bind data
    /// - Error (4): completion status
    fn parse_plsql_response(
        &self,
        payload: &[u8],
        caps: &Capabilities,
        params: &[BindParam],
    ) -> Result<PlsqlResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("PL/SQL response too short".to_string()));
        }

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut out_values: Vec<Value> = Vec::new();
        let mut _out_indices: Vec<usize> = Vec::new();
        let mut row_count: u64 = 0;
        let mut cursor_id: Option<u16> = None;
        let mut end_of_response = false;
        let mut implicit_results = ImplicitResults::new();

        // Create column infos for OUT params based on their oracle types
        let mut out_columns: Vec<ColumnInfo> = Vec::new();

        while !end_of_response && buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // IoVector (11) - bind directions from server
                x if x == MessageType::IoVector as u8 => {
                    let (indices, cols) = self.parse_io_vector(&mut buf, params)?;
                    _out_indices = indices;
                    out_columns = cols;
                }

                // RowHeader (6)
                x if x == MessageType::RowHeader as u8 => {
                    self.parse_row_header(&mut buf)?;
                }

                // RowData (7) - OUT parameter values
                x if x == MessageType::RowData as u8 => {
                    if !out_columns.is_empty() {
                        let row = self.parse_row_data_single(&mut buf, &out_columns, caps)?;
                        // Extract values from the row into out_values
                        for (idx, value) in row.into_values().into_iter().enumerate() {
                            // Check if this is a cursor
                            if let Value::Cursor(cursor) = &value {
                                if cursor_id.is_none() && cursor.cursor_id() != 0 {
                                    cursor_id = Some(cursor.cursor_id());
                                }
                            }
                            // Map back to original param position if we have indices
                            if idx < out_values.len() {
                                out_values[idx] = value;
                            } else {
                                out_values.push(value);
                            }
                        }
                    } else {
                        // Skip the row data if we don't have column info
                        // This shouldn't normally happen
                        break;
                    }
                }

                // DescribeInfo (16) - for REF CURSOR describe
                x if x == MessageType::DescribeInfo as u8 => {
                    buf.skip_raw_bytes_chunked()?;
                    let cursor_columns =
                        self.parse_describe_info(&mut buf, caps.ttc_field_version)?;
                    // Store cursor columns if needed
                    let _ = cursor_columns; // For now, just skip
                }

                // FlushOutBinds (19) - signals end of OUT bind data
                x if x == MessageType::FlushOutBinds as u8 => {
                    // This indicates that OUT bind data is done
                    // Just continue to get the error/completion status
                }

                // Error (4) - completion or error
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, _cid, rc) =
                        self.parse_error_info_with_rowcount(&mut buf, caps.ttc_field_version)?;
                    row_count = rc;
                    if error_code != 0 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                    end_of_response = true;
                }

                // Parameter (8) - return parameters
                x if x == MessageType::Parameter as u8 => {
                    self.parse_return_parameters(&mut buf)?;
                }

                // Status (9)
                x if x == MessageType::Status as u8 => {
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                }

                // ImplicitResultset (27) - result sets from DBMS_SQL.RETURN_RESULT
                x if x == MessageType::ImplicitResultset as u8 => {
                    let parsed_results = self.parse_implicit_results(&mut buf, caps)?;
                    implicit_results = parsed_results;
                }

                _ => {
                    // Unknown message type - break to avoid parsing errors
                    break;
                }
            }
        }

        // If no IoVector was received, all params might be IN-only
        // In that case, out_values should be empty
        Ok(PlsqlResult {
            out_values,
            rows_affected: row_count,
            cursor_id,
            implicit_results,
        })
    }

    /// Parse implicit result sets from DBMS_SQL.RETURN_RESULT
    ///
    /// Format per Python base.pyx _process_implicit_result:
    /// - num_results: ub4 (number of implicit result sets)
    /// - For each result:
    ///   - num_bytes: ub1 + raw bytes (metadata to skip)
    ///   - describe_info: column metadata
    ///   - cursor_id: ub2
    fn parse_implicit_results(
        &self,
        buf: &mut ReadBuffer,
        caps: &Capabilities,
    ) -> Result<ImplicitResults> {
        let num_results = buf.read_ub4()?;
        let mut results = ImplicitResults::new();

        for _ in 0..num_results {
            // Skip metadata bytes
            let num_bytes = buf.read_u8()?;
            if num_bytes > 0 {
                buf.skip(num_bytes as usize)?;
            }

            // Parse column metadata for this result set
            let columns = self.parse_describe_info(buf, caps.ttc_field_version)?;

            // Read cursor ID
            let cursor_id = buf.read_ub2()?;

            // Create implicit result with metadata but no rows yet
            // Rows will be fetched separately using fetch_implicit_result
            let result = ImplicitResult::new(cursor_id, columns, Vec::new());
            results.add(result);
        }

        Ok(results)
    }

    /// Parse IO Vector message to get bind directions
    ///
    /// Returns a tuple of:
    /// - indices of OUT/INOUT parameters in the params list
    /// - column infos for parsing OUT values
    fn parse_io_vector(
        &self,
        buf: &mut ReadBuffer,
        params: &[BindParam],
    ) -> Result<(Vec<usize>, Vec<ColumnInfo>)> {
        // I/O vector format (from Python reference):
        // - skip 1 byte (flag)
        // - read ub2 (num requests)
        // - read ub4 (num iters)
        // - num_binds = num_iters * 256 + num_requests
        // - skip ub4 (num iters this time)
        // - skip ub2 (uac buffer length)
        // - read ub2 (num_bytes for bit vector), skip if > 0
        // - read ub2 (num_bytes for rowid), skip if > 0
        // - for each bind: read ub1 (bind_dir)

        buf.skip(1)?; // flag
        let num_requests = buf.read_ub2()? as u32;
        let num_iters = buf.read_ub4()?;
        let num_binds = num_iters * 256 + num_requests;
        let _ = buf.read_ub4()?; // num iters this time (discard)
        let _ = buf.read_ub2()?; // uac buffer length (discard)

        // Bit vector
        let num_bytes = buf.read_ub2()? as usize;
        if num_bytes > 0 {
            buf.skip(num_bytes)?;
        }

        // Rowid (raw bytes, not length-prefixed here)
        let num_bytes = buf.read_ub4()? as usize;
        if num_bytes > 0 {
            buf.skip_raw_bytes_chunked()?; // Skip rowid bytes using chunked read
        }

        // Read bind directions
        let mut out_indices = Vec::new();
        let mut out_columns = Vec::new();

        for (i, param) in params
            .iter()
            .enumerate()
            .take((num_binds as usize).min(params.len()))
        {
            let dir_byte = buf.read_u8()?;
            let dir = BindDirection::try_from(dir_byte).unwrap_or(BindDirection::Input);

            // If this is not an INPUT-only parameter, it has OUT data
            if dir != BindDirection::Input {
                out_indices.push(i);

                // Create a column info for parsing the OUT value
                let mut col = ColumnInfo::new(format!("OUT_{}", i), param.oracle_type);
                col.buffer_size = param.buffer_size;
                col.data_size = param.buffer_size;
                col.nullable = true;

                // For collection OUT params, extract element type from the placeholder
                if let Some(Value::Collection(ref placeholder)) = param.value {
                    if let Some(Value::Integer(elem_type_code)) = placeholder.get("_element_type") {
                        col.element_type =
                            crate::constants::OracleType::try_from(*elem_type_code as u8).ok();
                    }
                }

                out_columns.push(col);
            }
        }

        Ok((out_indices, out_columns))
    }

    /// Parse row header (TNS_MSG_TYPE_ROW_HEADER = 6)
    fn parse_row_header(&self, buf: &mut ReadBuffer) -> Result<()> {
        buf.skip_ub1()?; // flags
        buf.skip_ub2()?; // num requests
        buf.skip_ub4()?; // iteration number
        buf.skip_ub4()?; // num iters
        buf.skip_ub2()?; // buffer length
        let num_bytes = buf.read_ub4()? as usize;
        if num_bytes > 0 {
            buf.skip_ub1()?; // skip repeated length
            buf.skip(num_bytes)?; // bit vector
        }
        let num_bytes = buf.read_ub4()? as usize;
        if num_bytes > 0 {
            buf.skip_raw_bytes_chunked()?; // rxhrid
        }
        Ok(())
    }

    /// Parse return parameters (TNS_MSG_TYPE_PARAMETER = 8)
    fn parse_return_parameters(&self, buf: &mut ReadBuffer) -> Result<()> {
        self.parse_return_parameters_internal(buf, false)
            .map(|_| ())
    }

    /// Parse return parameters with optional row counts extraction
    /// When `want_row_counts` is true, attempts to read arraydmlrowcounts from the response.
    fn parse_return_parameters_internal(
        &self,
        buf: &mut ReadBuffer,
        want_row_counts: bool,
    ) -> Result<Option<Vec<u64>>> {
        // Layout per go-ora command.go case 8:
        //   size      = UB2          (al8o4l count)
        //   [size]    = UB4 each     (SCN + remaining values)
        //   reg       = UB2          (registration)
        //   num_pairs = UB2
        //   [pairs]   = key(DLC) + val(DLC) + keyword_num(UB4)
        //   queryID   = UB4 size + bytes  (TTCVersion >= 4)
        //   rowcounts = UB4 count + UB8 each (TTCVersion >= 7)

        let num_params = buf.read_ub2()?;
        for _ in 0..num_params {
            buf.skip_ub4()?;
        }

        // registration
        let reg = buf.read_ub2()?;
        if reg > 0 {
            buf.skip(reg as usize)?;
        }

        // key/value pairs (DLC format: UB4 length, then CLR chunked data)
        let num_pairs = buf.read_ub2()?;
        for _ in 0..num_pairs {
            // key: UB4 length + chunked bytes
            let key_len = buf.read_ub4()?;
            if key_len > 0 {
                buf.skip_raw_bytes_chunked()?;
            }
            // value: UB4 length + chunked bytes
            let val_len = buf.read_ub4()?;
            if val_len > 0 {
                buf.skip_raw_bytes_chunked()?;
            }
            // keyword num (UB4)
            buf.skip_ub4()?;
        }

        // queryID (TTCVersion >= 4)
        {
            let qid_size = buf.read_ub4()? as usize;
            if qid_size > 0 {
                buf.skip(qid_size)?;
            }
        }

        // If arraydmlrowcounts was requested, parse the row counts
        if want_row_counts && buf.remaining() >= 4 {
            let num_rows = buf.read_ub4()? as usize;
            let mut row_counts = Vec::with_capacity(num_rows);
            for _ in 0..num_rows {
                let count = buf.read_ub8()?;
                row_counts.push(count);
            }
            Ok(Some(row_counts))
        } else {
            Ok(None)
        }
    }

    /// Parse a single row of data
    fn parse_row_data_single(
        &self,
        buf: &mut ReadBuffer,
        columns: &[ColumnInfo],
        caps: &Capabilities,
    ) -> Result<Row> {
        let mut values = Vec::with_capacity(columns.len());

        for col in columns {
            let value = self.parse_column_value(buf, col, caps)?;
            values.push(value);
        }

        Ok(Row::new(values))
    }

    /// Parse a single row of data with bit vector support for duplicate column optimization
    ///
    /// Oracle sends a BitVector message before RowData when some columns have the same
    /// value as the previous row. Bits that are SET (1) indicate data is sent in the buffer;
    /// bits that are CLEAR (0) indicate the value should be copied from the previous row.
    fn parse_row_data_with_bitvector(
        &self,
        buf: &mut ReadBuffer,
        columns: &[ColumnInfo],
        caps: &Capabilities,
        bit_vector: Option<&[u8]>,
        previous_values: Option<&Vec<Value>>,
    ) -> Result<Row> {
        let mut values = Vec::with_capacity(columns.len());

        for (col_idx, col) in columns.iter().enumerate() {
            // Check if this column is a duplicate (bit=0 means duplicate)
            let is_duplicate = if let Some(bv) = bit_vector {
                let byte_num = col_idx / 8;
                let bit_num = col_idx % 8;
                if byte_num < bv.len() {
                    // If bit is 0, it's a duplicate
                    (bv[byte_num] & (1 << bit_num)) == 0
                } else {
                    false
                }
            } else {
                false
            };

            if is_duplicate {
                // Copy value from previous row
                if let Some(prev) = previous_values {
                    if col_idx < prev.len() {
                        values.push(prev[col_idx].clone());
                    } else {
                        // Shouldn't happen, but fallback to null
                        values.push(Value::Null);
                    }
                } else {
                    // No previous row (shouldn't happen for duplicate), fallback to null
                    values.push(Value::Null);
                }
            } else {
                // Read actual value from buffer
                let value = self.parse_column_value(buf, col, caps)?;
                values.push(value);
            }
        }

        Ok(Row::new(values))
    }

    /// Parse a single column value from the buffer
    fn parse_column_value(
        &self,
        buf: &mut ReadBuffer,
        col: &ColumnInfo,
        caps: &Capabilities,
    ) -> Result<Value> {
        use crate::constants::OracleType;

        // Handle LOB columns specially - they have a different format
        if col.is_lob() {
            return self.parse_lob_value(buf, col);
        }

        // Handle CURSOR type - REF CURSOR from PL/SQL
        if col.oracle_type == OracleType::Cursor {
            return self.parse_cursor_value(buf, caps);
        }

        // Handle Object type - collections (VARRAY, Nested Table) and UDTs
        if col.oracle_type == OracleType::Object {
            return self.parse_object_value(buf, col);
        }

        // Read the value based on the column type
        // First, check if it's NULL
        let data = buf.read_bytes_with_length()?;

        match data {
            None => Ok(Value::Null),
            Some(bytes) if bytes.is_empty() => Ok(Value::Null),
            Some(bytes) => {
                // Decode based on oracle type
                match col.oracle_type {
                    OracleType::Number => {
                        // Oracle NUMBER format - decode to string
                        let num = crate::types::decode_oracle_number(&bytes)?;
                        Ok(Value::String(num.value))
                    }
                    OracleType::Varchar | OracleType::Char | OracleType::Long => {
                        let s = String::from_utf8_lossy(&bytes).to_string();
                        Ok(Value::String(s))
                    }
                    OracleType::Raw | OracleType::LongRaw => {
                        // RAW/LONG RAW types - return as bytes
                        Ok(Value::Bytes(bytes.to_vec()))
                    }
                    OracleType::Date => {
                        // Oracle DATE format - 7 bytes
                        let date = crate::types::decode_oracle_date(&bytes)?;
                        Ok(Value::Date(date))
                    }
                    OracleType::Timestamp | OracleType::TimestampLtz => {
                        // Oracle TIMESTAMP format - 11 bytes (date + fractional seconds)
                        let ts = crate::types::decode_oracle_timestamp(&bytes)?;
                        Ok(Value::Timestamp(ts))
                    }
                    OracleType::TimestampTz => {
                        // Oracle TIMESTAMP WITH TIME ZONE - 13 bytes
                        let ts = crate::types::decode_oracle_timestamp(&bytes)?;
                        Ok(Value::Timestamp(ts))
                    }
                    _ => {
                        // Default: return as raw bytes or string
                        let s = String::from_utf8_lossy(&bytes).to_string();
                        Ok(Value::String(s))
                    }
                }
            }
        }
    }

    /// Parse a REF CURSOR value from the buffer
    ///
    /// Per Python base.pyx lines 1038-1046:
    /// - Skip 1 byte (length indicator - fixed value)
    /// - Read describe info (column metadata for the cursor)
    /// - Read cursor_id (UB2)
    fn parse_cursor_value(&self, buf: &mut ReadBuffer, caps: &Capabilities) -> Result<Value> {
        use crate::types::RefCursor;

        // Skip length indicator (fixed value for cursors)
        let _length = buf.read_u8()?;

        // Read column metadata for this cursor
        let cursor_columns = self.parse_describe_info(buf, caps.ttc_field_version)?;

        // Read the cursor ID
        let cursor_id = buf.read_ub2()?;

        // Create RefCursor with the metadata
        let ref_cursor = RefCursor::new(cursor_id, cursor_columns);

        Ok(Value::Cursor(ref_cursor))
    }

    /// Parse an Object/Collection value from the buffer
    ///
    /// Object format from Oracle (per Python packet.pyx read_dbobject):
    /// - UB4: type OID length, then type OID bytes if > 0
    /// - UB4: OID length, then OID bytes if > 0
    /// - UB4: snapshot length, then snapshot bytes if > 0 (discarded)
    /// - UB2: version (skip)
    /// - UB4: packed data length
    /// - UB2: flags (skip)
    /// - Bytes: packed data (pickle format)
    fn parse_object_value(&self, buf: &mut ReadBuffer, col: &ColumnInfo) -> Result<Value> {
        use crate::dbobject::{CollectionType, DbObject, DbObjectType};
        use crate::types::decode_collection;

        // Read type OID
        let toid_len = buf.read_ub4()?;
        let _toid = if toid_len > 0 {
            Some(buf.read_bytes_vec(toid_len as usize)?)
        } else {
            None
        };

        // Read OID
        let oid_len = buf.read_ub4()?;
        let _oid = if oid_len > 0 {
            Some(buf.read_bytes_vec(oid_len as usize)?)
        } else {
            None
        };

        // Read and discard snapshot
        let snapshot_len = buf.read_ub4()?;
        if snapshot_len > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Skip version (length-prefixed UB2)
        let _version = buf.read_ub2()?;

        // Read packed data length
        let data_len = buf.read_ub4()?;

        // Skip flags (length-prefixed UB2)
        let _flags = buf.read_ub2()?;

        if data_len == 0 {
            return Ok(Value::Null);
        }

        // Read packed data (chunked format like other byte sequences)
        let packed_data = buf.read_bytes_with_length()?;

        match packed_data {
            None => Ok(Value::Null),
            Some(data) if data.is_empty() => Ok(Value::Null),
            Some(data) => {
                // Create a placeholder type based on column info
                let type_name = col
                    .type_name
                    .clone()
                    .unwrap_or_else(|| "UNKNOWN".to_string());

                // Try to determine if this is a collection based on the pickle data
                // The first byte contains flags - check for IS_COLLECTION (0x08)
                let is_collection = !data.is_empty() && (data[0] & 0x08) != 0;

                if is_collection {
                    // Get element type from column info or default to VARCHAR
                    let element_type = col
                        .element_type
                        .unwrap_or(crate::constants::OracleType::Varchar);

                    // Determine collection type from pickle flags
                    // Collection flags are after header - but we'll default for now
                    let collection_type = CollectionType::Varray;

                    let obj_type = DbObjectType::collection(
                        col.type_schema.clone().unwrap_or_default(),
                        &type_name,
                        collection_type,
                        element_type,
                    );

                    match decode_collection(&obj_type, &data) {
                        Ok(collection) => Ok(Value::Collection(collection)),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to decode collection: {}, data: {:02x?}",
                                e,
                                &data[..std::cmp::min(20, data.len())]
                            );
                            // Return raw bytes as fallback
                            Ok(Value::Bytes(data))
                        }
                    }
                } else {
                    // Regular object type - not yet fully implemented
                    let mut obj = DbObject::new(&type_name);
                    // Store raw pickle data for later inspection
                    obj.set("_raw_data", Value::Bytes(data));
                    Ok(Value::Collection(obj))
                }
            }
        }
    }

    /// Parse a LOB column value from the buffer
    ///
    /// LOB format from Oracle (per Python's read_lob_with_length):
    /// - UB4: num_bytes (indicator that LOB data follows)
    /// - If num_bytes > 0:
    ///   - For non-BFILE: UB8 size, UB4 chunk_size
    ///   - Bytes: LOB locator (chunked format)
    ///
    /// The actual LOB content must be fetched separately using LOB operations.
    /// For JSON columns, the data is OSON-encoded and decoded directly.
    /// For VECTOR columns, the data is decoded from Oracle's vector binary format.
    fn parse_lob_value(&self, buf: &mut ReadBuffer, col: &ColumnInfo) -> Result<Value> {
        use crate::constants::OracleType;
        use crate::types::{decode_vector, OsonDecoder};

        // Read length indicator
        let num_bytes = buf.read_ub4()?;

        if num_bytes == 0 {
            // For JSON, null is Value::Json(serde_json::Value::Null)
            if col.oracle_type == OracleType::Json || col.is_json {
                return Ok(Value::Json(serde_json::Value::Null));
            }
            // For VECTOR, null is Value::Null
            if col.oracle_type == OracleType::Vector {
                return Ok(Value::Null);
            }
            return Ok(Value::Lob(LobValue::Null));
        }

        // For BFILE, there's no size/chunk_size metadata
        let (size, chunk_size) = if col.oracle_type == OracleType::Bfile {
            (0u64, 0u32)
        } else {
            // Read LOB size and chunk size
            let size = buf.read_ub8()?;
            let chunk_size = buf.read_ub4()?;
            (size, chunk_size)
        };

        // Read LOB data (could be locator or inline data depending on size)
        let data_bytes = buf.read_bytes_with_length()?;

        // Handle JSON columns - decode OSON format
        // JSON is sent as a LOB with prefetched data + a LOB locator that must be consumed
        if col.oracle_type == OracleType::Json || col.is_json {
            // Read and discard the LOB locator
            let _locator = buf.read_bytes_with_length()?;

            if let Some(data) = data_bytes {
                if !data.is_empty() {
                    // Decode OSON to JSON
                    match OsonDecoder::decode(bytes::Bytes::from(data)) {
                        Ok(json_value) => return Ok(Value::Json(json_value)),
                        Err(e) => {
                            tracing::warn!("Failed to decode OSON: {}", e);
                            return Ok(Value::Json(serde_json::Value::Null));
                        }
                    }
                }
            }
            return Ok(Value::Json(serde_json::Value::Null));
        }

        // Handle VECTOR columns - decode vector binary format
        if col.oracle_type == OracleType::Vector {
            // Read and discard LOB locator (not needed for VECTOR)
            let _locator = buf.read_bytes_with_length()?;

            if let Some(data) = data_bytes {
                if !data.is_empty() {
                    match decode_vector(&data) {
                        Ok(vector) => return Ok(Value::Vector(vector)),
                        Err(e) => {
                            tracing::warn!("Failed to decode VECTOR: {}", e);
                            return Ok(Value::Null);
                        }
                    }
                }
            }
            return Ok(Value::Null);
        }

        // Create a LOB locator for fetching the data later
        if let Some(locator_data) = data_bytes {
            if !locator_data.is_empty() {
                let locator = LobLocator::new(
                    bytes::Bytes::from(locator_data),
                    size,
                    chunk_size,
                    col.oracle_type,
                    col.csfrm,
                );
                return Ok(Value::Lob(LobValue::locator(locator)));
            }
        }

        // If we have size but no locator, it might be an empty LOB
        if size == 0 {
            return Ok(Value::Lob(LobValue::Empty));
        }

        // Empty LOB (shouldn't normally reach here)
        Ok(Value::Lob(LobValue::Empty))
    }

    /// Parse error info message and extract cursor_id
    /// Format per Python's _process_error_info in base.pyx
    fn parse_error_info(&self, buf: &mut ReadBuffer) -> Result<(u32, Option<String>, u16)> {
        // End of call status
        let _call_status = buf.read_ub4()?;
        // End to end seq#
        buf.skip_ub2()?;
        // Current row number
        buf.skip_ub4()?;
        // Error number (short form)
        let error_num_short = buf.read_ub2()? as u32;
        // Array elem error
        buf.skip_ub2()?;
        // Array elem error
        buf.skip_ub2()?;
        // Cursor ID
        let cursor_id = buf.read_ub2()?;
        // Error position
        let _error_pos = buf.read_sb2()?;
        // SQL type (19c and earlier)
        buf.skip_ub1()?;
        // Fatal?
        buf.skip_ub1()?;
        // Flags
        buf.skip_ub1()?;
        // User cursor options
        buf.skip_ub1()?;
        // UPI parameter
        buf.skip_ub1()?;
        // Flags (second)
        buf.skip_ub1()?;
        // Rowid (rba, partition_id, skip 1, block_num, slot_num)
        buf.skip_ub4()?; // rba
        buf.skip_ub2()?; // partition_id
        buf.skip_ub1()?; // skip
        buf.skip_ub4()?; // block_num
        buf.skip_ub2()?; // slot_num
                         // OS error
        buf.skip_ub4()?;
        // Statement number
        buf.skip_ub1()?;
        // Call number
        buf.skip_ub1()?;
        // Padding
        buf.skip_ub2()?;
        // Success iters
        buf.skip_ub4()?;
        // oerrdd (logical rowid)
        let oerrdd_len = buf.read_ub4()?;
        if oerrdd_len > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Batch error codes array
        let num_batch_errors = buf.read_ub2()?;
        if num_batch_errors > 0 {
            buf.skip_ub1()?; // first byte
            for _ in 0..num_batch_errors {
                buf.skip_ub2()?; // error code
            }
        }

        // Batch error row offset array
        let num_offsets = buf.read_ub4()?;
        if num_offsets > 0 {
            buf.skip_ub1()?; // first byte
            for _ in 0..num_offsets {
                buf.skip_ub4()?; // offset
            }
        }

        // Batch error messages array
        let num_batch_msgs = buf.read_ub2()?;
        if num_batch_msgs > 0 {
            buf.skip_ub1()?; // packed size
            for _ in 0..num_batch_msgs {
                buf.skip_ub2()?; // chunk length
                buf.read_string_with_length()?; // message
                buf.skip(2)?; // end marker
            }
        }

        let (error_code, _, _) = self.read_optional_extended_error_info(buf, error_num_short, 0)?;

        // Error message
        let error_msg = self.read_optional_error_message(buf, error_code)?;

        Ok((error_code, error_msg, cursor_id))
    }

    fn read_optional_extended_error_info(
        &self,
        buf: &mut ReadBuffer,
        short_error_code: u32,
        fallback_row_count: u64,
    ) -> Result<(u32, u64, bool)> {
        let saved_pos = buf.position();
        let extended_error_code = match buf.read_ub4() {
            Ok(value) => value,
            Err(Error::InvalidLengthIndicator(_) | Error::BufferUnderflow { .. }) => {
                let _ = buf.set_position(saved_pos);
                return Ok((short_error_code, fallback_row_count, false));
            }
            Err(err) => return Err(err),
        };

        let row_count = match buf.read_ub8() {
            Ok(value) => value,
            Err(Error::InvalidLengthIndicator(_) | Error::BufferUnderflow { .. }) => {
                let _ = buf.set_position(saved_pos);
                return Ok((short_error_code, fallback_row_count, false));
            }
            Err(err) => return Err(err),
        };

        let error_code = if extended_error_code != 0 {
            extended_error_code
        } else {
            short_error_code
        };
        Ok((error_code, row_count, true))
    }

    fn read_optional_error_message(
        &self,
        buf: &mut ReadBuffer,
        error_code: u32,
    ) -> Result<Option<String>> {
        if error_code == 0 {
            return Ok(None);
        }

        match buf.read_string_with_length() {
            Ok(message) => Ok(message.map(|s| s.trim().to_string())),
            Err(Error::InvalidLengthIndicator(_)) => {
                let raw = String::from_utf8_lossy(buf.remaining_bytes())
                    .trim()
                    .to_string();
                if raw.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(raw))
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Parse error response packet (received after marker reset)
    fn parse_error_response(&self, payload: &[u8]) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("Error response too short".to_string()));
        }

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        // Read message type
        let msg_type = buf.read_u8()?;

        // Check for error message type (4)
        if msg_type == MessageType::Error as u8 {
            // Parse error info per Python's _process_error_info
            let _call_status = buf.read_ub4()?; // end of call status
            buf.skip_ub2()?; // end to end seq#
            buf.skip_ub4()?; // current row number
            let error_num_short = buf.read_ub2()? as u32; // error number (short form)
            buf.skip_ub2()?; // array elem error
            buf.skip_ub2()?; // array elem error
            let _cursor_id = buf.read_ub2()?; // cursor id
            let _error_pos = buf.read_sb2()?; // error position
            buf.skip_ub1()?; // sql type (19c and earlier)
            buf.skip_ub1()?; // fatal?
            buf.skip_ub1()?; // flags
            buf.skip_ub1()?; // user cursor options
            buf.skip_ub1()?; // UPI parameter
            buf.skip_ub1()?; // flags

            // Rowid (rba, partition_id, skip 1, block_num, slot_num)
            buf.skip_ub4()?; // rba
            buf.skip_ub2()?; // partition_id
            buf.skip_ub1()?; // skip
            buf.skip_ub4()?; // block_num
            buf.skip_ub2()?; // slot_num

            buf.skip_ub4()?; // OS error
            buf.skip_ub1()?; // statement number
            buf.skip_ub1()?; // call number
            buf.skip_ub2()?; // padding
            buf.skip_ub4()?; // success iters

            // oerrdd (logical rowid)
            let oerrdd_len = buf.read_ub4()?;
            if oerrdd_len > 0 {
                buf.skip_raw_bytes_chunked()?;
            }

            // batch error codes array
            let num_batch_errors = buf.read_ub2()?;
            if num_batch_errors > 0 {
                buf.skip_ub1()?;
                for _ in 0..num_batch_errors {
                    buf.skip_ub2()?;
                }
            }

            // batch error row offset array
            let num_offsets = buf.read_ub4()?;
            if num_offsets > 0 {
                buf.skip_ub1()?;
                for _ in 0..num_offsets {
                    buf.skip_ub4()?;
                }
            }

            // batch error messages array
            let num_batch_msgs = buf.read_ub2()?;
            if num_batch_msgs > 0 {
                buf.skip_ub1()?;
                for _ in 0..num_batch_msgs {
                    buf.skip_ub2()?;
                    buf.read_string_with_length()?;
                    buf.skip(2)?;
                }
            }

            // Extended error number (UB4) + row count (UB8).
            // Oracle 11g (ttc_field_version == 6) does not send these fields;
            // the error message follows directly after the batch arrays. These
            // two helpers rewind and fall back exactly as needed for both the
            // 11g short-error layout and the modern extended-error layout.
            let (error_num, _row_count, _read_extended_info) =
                self.read_optional_extended_error_info(&mut buf, error_num_short, 0)?;

            // Read error message
            let error_msg = self.read_optional_error_message(&mut buf, error_num)?;

            return Err(Error::OracleError {
                code: error_num,
                message: error_msg.unwrap_or_else(|| format!("ORA-{:05}", error_num)),
            });
        }

        // If not an error message type, return generic error
        Err(Error::Protocol(format!(
            "Expected error message type 4, got {}",
            msg_type
        )))
    }

    /// Parse DML response to extract rows affected
    fn parse_dml_response(&self, payload: &[u8], ttc_field_version: u8) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("DML response too short".to_string()));
        }

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut rows_affected: u64 = 0;
        let mut cursor_id: u16 = 0;
        let mut end_of_response = false;

        // Process messages until end_of_response or out of data
        // Note: If supports_end_of_response is true, we must continue until msg type 29
        while !end_of_response && buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Error (4) - may contain error or success info
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, cid, row_count) =
                        self.parse_error_info_with_rowcount(&mut buf, ttc_field_version)?;
                    cursor_id = cid;
                    rows_affected = row_count;
                    if error_code != 0 && error_code != 1403 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                    // Only end if server doesn't support end_of_response
                    // Otherwise, continue until we get msg type 29
                }

                // Parameter (8) - return parameters
                x if x == MessageType::Parameter as u8 => {
                    self.parse_return_parameters(&mut buf)?;
                }

                // Status (9) - call status
                x if x == MessageType::Status as u8 => {
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                }

                // BitVector (21)
                21 => {
                    let _num_columns_sent = buf.read_ub2()?;
                    // No columns for DML, but read the byte if present
                    if buf.remaining() > 0 {
                        let _byte = buf.read_u8()?;
                    }
                }

                // End of Response (29) - explicit end marker
                29 => {
                    end_of_response = true;
                }

                _ => {
                    // Unknown message type - continue processing
                }
            }
        }

        Ok(QueryResult {
            columns: Vec::new(),
            rows: Vec::new(),
            rows_affected,
            has_more_rows: false,
            cursor_id,
        })
    }

    /// Parse error info and return (error_code, error_msg, cursor_id, row_count)
    fn parse_error_info_with_rowcount(
        &self,
        buf: &mut ReadBuffer,
        ttc_field_version: u8,
    ) -> Result<(u32, Option<String>, u16, u64)> {
        use crate::constants::ccap_value;

        // End of call status
        let _call_status = buf.read_ub4()?;
        // End to end seq#
        buf.skip_ub2()?;
        // Current row number. On Oracle 11g DML success responses this is the
        // only row-count-like value present; newer servers also send the
        // extended row count later in this message.
        let current_row_number = buf.read_ub4()?;
        // Error number (short form)
        let error_num_short = buf.read_ub2()? as u32;
        // Array elem error
        buf.skip_ub2()?;
        // Array elem error
        buf.skip_ub2()?;
        // Cursor ID
        let cursor_id = buf.read_ub2()?;
        // Error position
        let _error_pos = buf.read_sb2()?;
        // SQL type (19c and earlier)
        buf.skip_ub1()?;
        // Fatal?
        buf.skip_ub1()?;
        // Flags
        buf.skip_ub1()?;
        // User cursor options
        buf.skip_ub1()?;
        // UPI parameter
        buf.skip_ub1()?;
        // Flags (second)
        buf.skip_ub1()?;
        // Rowid (rba, partition_id, skip 1, block_num, slot_num)
        buf.skip_ub4()?; // rba
        buf.skip_ub2()?; // partition_id
        buf.skip_ub1()?; // skip
        buf.skip_ub4()?; // block_num
        buf.skip_ub2()?; // slot_num
                         // OS error
        buf.skip_ub4()?;
        // Statement number
        buf.skip_ub1()?;
        // Call number
        buf.skip_ub1()?;
        // Padding
        buf.skip_ub2()?;
        // Success iters
        buf.skip_ub4()?;
        // oerrdd (logical rowid)
        let oerrdd_len = buf.read_ub4()?;
        if oerrdd_len > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Batch error codes array
        let num_batch_errors = buf.read_ub2()?;
        if num_batch_errors > 0 {
            buf.skip_ub1()?;
            for _ in 0..num_batch_errors {
                buf.skip_ub2()?;
            }
        }

        // Batch error row offset array
        let num_offsets = buf.read_ub4()?;
        if num_offsets > 0 {
            buf.skip_ub1()?;
            for _ in 0..num_offsets {
                buf.skip_ub4()?;
            }
        }

        // Batch error messages array
        let num_batch_msgs = buf.read_ub2()?;
        if num_batch_msgs > 0 {
            buf.skip_ub1()?;
            for _ in 0..num_batch_msgs {
                buf.skip_ub2()?;
                buf.read_string_with_length()?;
                buf.skip(2)?;
            }
        }

        let (error_code, row_count, read_extended_info) = self.read_optional_extended_error_info(
            buf,
            error_num_short,
            current_row_number as u64,
        )?;

        // sql_type + server_checksum were added in Oracle 20c; python-oracledb
        // gates them on TNS_CCAP_FIELD_VERSION_20_1 (14).
        if ttc_field_version >= ccap_value::FIELD_VERSION_20_1 && read_extended_info {
            buf.skip_ub4()?; // sql_type
            buf.skip_ub4()?; // server_checksum
        }

        // Error message
        let error_msg = self.read_optional_error_message(buf, error_code)?;

        Ok((error_code, error_msg, cursor_id, row_count))
    }

    /// Parse describe info from response to extract column metadata
    ///
    /// Per Python's _process_describe_info, the format is:
    /// - UB4: max row size (skip)
    /// - UB4: number of columns
    /// - If num_columns > 0: UB1 (skip one byte)
    /// - For each column: metadata fields
    /// - After columns: current date, dcb flags, etc.
    fn parse_describe_info(
        &self,
        buf: &mut ReadBuffer,
        ttc_field_version: u8,
    ) -> Result<Vec<ColumnInfo>> {
        use crate::constants::ccap_value;

        // Skip max row size
        buf.skip_ub4()?;

        // Read number of columns
        let num_columns = buf.read_ub4()? as usize;
        if num_columns == 0 {
            return Ok(Vec::new());
        }

        // Skip one byte if we have columns
        buf.skip_ub1()?;

        let mut columns = Vec::with_capacity(num_columns);

        for _col_idx in 0..num_columns {
            // Parse column metadata per Python's _process_metadata
            let ora_type_num = buf.read_u8()?;
            buf.skip_ub1()?; // flags
            let precision = buf.read_u8()?; // precision as SB1
            let scale = buf.read_u8()?; // scale as SB1
            let buffer_size = buf.read_ub4()?;

            buf.skip_ub4()?; // max_num_array_elements
            buf.skip_ub8()?; // cont_flags
            let oid_length = buf.read_ub4()?; // OID length
            if oid_length > 0 {
                buf.skip_raw_bytes_chunked()?; // skip OID bytes
            }
            buf.skip_ub2()?; // version
            buf.skip_ub2()?; // charset_id
            let _csfrm = buf.read_u8()?; // charset form
            let max_size = buf.read_ub4()?;

            // For TTC field version >= 12.2 (8), skip oaccolid
            if ttc_field_version >= ccap_value::FIELD_VERSION_12_2 {
                buf.skip_ub4()?; // oaccolid
            }

            let _nulls_allowed = buf.read_u8()?;
            buf.skip_ub1()?; // v7 length of name
            let name = buf.read_string_with_ub4_length()?.unwrap_or_default();
            let _schema = buf.read_string_with_ub4_length()?; // schema
            let _type_name = buf.read_string_with_ub4_length()?; // type_name
            buf.skip_ub2()?; // column position
            buf.skip_ub4()?; // uds_flags

            // For TTC field version >= 23.1 (17), read domain fields
            if ttc_field_version >= ccap_value::FIELD_VERSION_23_1 {
                let _domain_schema = buf.read_string_with_ub4_length()?;
                let _domain_name = buf.read_string_with_ub4_length()?;
            }

            // For TTC field version >= 20 (23.1_EXT_3), read annotations
            if ttc_field_version >= 20 {
                let num_annotations = buf.read_ub4()?;
                if num_annotations > 0 {
                    buf.skip_ub1()?;
                    // Read the actual annotations count (yes, it's read twice in Python)
                    let actual_num = buf.read_ub4()?;
                    buf.skip_ub1()?;
                    for _ in 0..actual_num {
                        // Skip annotation key and value (both are string with UB4 length)
                        let _key = buf.read_string_with_ub4_length()?;
                        let _value = buf.read_string_with_ub4_length()?;
                        buf.skip_ub4()?; // flags per annotation
                    }
                    buf.skip_ub4()?; // final flags
                }
            }

            // For TTC field version >= 24 (23.4), read vector fields
            if ttc_field_version >= ccap_value::FIELD_VERSION_23_4 {
                buf.skip_ub4()?; // vector_dimensions
                buf.skip_ub1()?; // vector_format
                buf.skip_ub1()?; // vector_flags
            }

            // Convert data type to OracleType
            let oracle_type = crate::constants::OracleType::try_from(ora_type_num)
                .unwrap_or(crate::constants::OracleType::Varchar);

            let mut col = ColumnInfo::new(&name, oracle_type);
            col.data_size = if max_size > 0 { max_size } else { buffer_size };
            col.precision = precision as i16;
            col.scale = scale as i16;
            columns.push(col);
        }

        // After columns: skip remaining describe info fields
        // Python's _process_describe_info uses:
        //   buf.read_ub4(&num_bytes)
        //   if num_bytes > 0:
        //       buf.skip_raw_bytes_chunked()    # current date
        //   buf.skip_ub4()                      # dcbflag
        //   buf.skip_ub4()                      # dcbmdbz
        //   buf.skip_ub4()                      # dcbmnpr
        //   buf.skip_ub4()                      # dcbmxpr
        //   buf.read_ub4(&num_bytes)
        //   if num_bytes > 0:
        //       buf.skip_raw_bytes_chunked()    # dcbqcky

        // current_date - read UB4 indicator first, then skip chunked bytes if > 0
        let current_date_indicator = buf.read_ub4()?;
        if current_date_indicator > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // dcb* fields as UB4
        buf.skip_ub4()?; // dcbflag
        buf.skip_ub4()?; // dcbmdbz
        buf.skip_ub4()?; // dcbmnpr
        buf.skip_ub4()?; // dcbmxpr

        // dcbqcky - read UB4 indicator first, then skip chunked bytes if > 0
        let dcbqcky_indicator = buf.read_ub4()?;
        if dcbqcky_indicator > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // After dcbqcky, the next message (RowHeader) follows directly
        // No additional fields to skip here

        Ok(columns)
    }

    /// Commit the current transaction.
    ///
    /// Makes all changes in the current transaction permanent. After commit,
    /// a new transaction begins automatically.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use oracle_rs::{Connection, Value};
    /// # async fn example(conn: Connection) -> oracle_rs::Result<()> {
    /// conn.execute("INSERT INTO users (name) VALUES (:1)", &["Alice".into()]).await?;
    /// conn.execute("INSERT INTO users (name) VALUES (:1)", &["Bob".into()]).await?;
    /// conn.commit().await?; // Both inserts are now permanent
    /// # Ok(())
    /// # }
    /// ```
    pub async fn commit(&self) -> Result<()> {
        self.ensure_ready().await?;
        // Use SQL COMMIT statement instead of simple function
        // The simple function protocol triggers BREAK marker + connection close on Oracle Free 23ai
        self.execute("COMMIT", &[]).await?;
        Ok(())
    }

    /// Rollback the current transaction.
    ///
    /// Discards all changes made in the current transaction. After rollback,
    /// a new transaction begins automatically.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use oracle_rs::{Connection, Value};
    /// # async fn example(conn: Connection) -> oracle_rs::Result<()> {
    /// conn.execute("DELETE FROM users WHERE id = :1", &[1.into()]).await?;
    /// // Oops, wrong user!
    /// conn.rollback().await?; // Delete is undone
    /// # Ok(())
    /// # }
    /// ```
    pub async fn rollback(&self) -> Result<()> {
        self.ensure_ready().await?;
        // Use SQL ROLLBACK statement instead of simple function
        // The simple function protocol triggers BREAK marker + connection close on Oracle Free 23ai
        self.execute("ROLLBACK", &[]).await?;
        Ok(())
    }

    /// Create a savepoint within the current transaction
    ///
    /// Savepoints allow partial rollback of a transaction. You can create multiple
    /// savepoints and rollback to any of them without affecting work done before
    /// that savepoint.
    ///
    /// # Arguments
    /// * `name` - The savepoint name (must be a valid Oracle identifier)
    ///
    /// # Example
    /// ```rust,ignore
    /// conn.execute("INSERT INTO t VALUES (1)", &[]).await?;
    /// conn.savepoint("sp1").await?;
    /// conn.execute("INSERT INTO t VALUES (2)", &[]).await?;
    /// conn.rollback_to_savepoint("sp1").await?; // Undoes the second insert
    /// conn.commit().await?; // Commits only the first insert
    /// ```
    pub async fn savepoint(&self, name: &str) -> Result<()> {
        self.ensure_ready().await?;
        self.execute(&format!("SAVEPOINT {}", name), &[]).await?;
        Ok(())
    }

    /// Rollback to a previously created savepoint
    ///
    /// This undoes all changes made after the savepoint was created, but keeps
    /// the transaction active. Changes made before the savepoint are preserved.
    ///
    /// # Arguments
    /// * `name` - The savepoint name to rollback to
    pub async fn rollback_to_savepoint(&self, name: &str) -> Result<()> {
        self.ensure_ready().await?;
        self.execute(&format!("ROLLBACK TO SAVEPOINT {}", name), &[])
            .await?;
        Ok(())
    }

    /// Ping the server to check if the connection is still alive.
    ///
    /// This executes a lightweight query (`SELECT 1 FROM DUAL`) to verify
    /// the connection is responsive. Useful for connection health checks
    /// in pooling scenarios.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use oracle_rs::Connection;
    /// # async fn example(conn: Connection) -> oracle_rs::Result<()> {
    /// if conn.ping().await.is_ok() {
    ///     println!("Connection is alive");
    /// } else {
    ///     println!("Connection is dead");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn ping(&self) -> Result<()> {
        self.ensure_ready().await?;
        // Use SELECT FROM DUAL instead of simple function
        // The simple function protocol triggers BREAK marker + connection close on Oracle Free 23ai
        self.query("SELECT 1 FROM DUAL", &[]).await?;
        Ok(())
    }

    /// Clear the statement cache
    ///
    /// This should be called when recycling a connection in a pool to ensure
    /// that any stale cursor state is cleared. This is useful after errors
    /// or when the connection state may be inconsistent.
    pub async fn clear_statement_cache(&self) {
        let mut inner = self.inner.lock().await;
        if let Some(ref mut cache) = inner.statement_cache {
            cache.clear();
        }
    }

    fn extract_embedded_server_error(packet: &[u8]) -> Option<String> {
        for needle in [b"ORA-".as_slice(), b"TNS-".as_slice()] {
            if let Some(offset) = packet
                .windows(needle.len())
                .position(|window| window == needle)
            {
                let tail = &packet[offset..];
                let end = tail
                    .iter()
                    .position(|byte| *byte == 0 || *byte == b'\n')
                    .unwrap_or(tail.len());
                return Some(String::from_utf8_lossy(&tail[..end]).to_string());
            }
        }

        None
    }

    /// Read data from a LOB (CLOB or BLOB)
    ///
    /// # Arguments
    /// * `locator` - The LOB locator obtained from a query result
    /// * `offset` - Starting position (1-based, in characters for CLOB, bytes for BLOB)
    /// * `amount` - Amount to read (0 for entire LOB)
    ///
    /// # Returns
    /// For CLOB: returns the text content as a String
    /// For BLOB: returns the binary content as bytes
    pub async fn read_lob(&self, locator: &LobLocator) -> Result<LobData> {
        self.ensure_ready().await?;

        // Read the entire LOB starting at offset 1
        let offset = 1u64;
        let amount = if locator.size() == 0 {
            self.lob_length(locator).await?
        } else {
            locator.size()
        };

        self.read_lob_internal(locator, offset, amount).await
    }

    /// Read a portion of a LOB
    pub async fn read_lob_range(
        &self,
        locator: &LobLocator,
        offset: u64,
        amount: u64,
    ) -> Result<LobData> {
        self.ensure_ready().await?;
        self.read_lob_internal(locator, offset, amount).await
    }

    /// Read a CLOB and return as String
    ///
    /// This is a convenience method for reading CLOB data directly as a String.
    /// Returns an error if the LOB is not a CLOB.
    pub async fn read_clob(&self, locator: &LobLocator) -> Result<String> {
        if locator.is_blob() || locator.is_bfile() {
            return Err(Error::Protocol(
                "Cannot read BLOB/BFILE as string, use read_blob instead".to_string(),
            ));
        }

        let data = self.read_lob(locator).await?;
        match data {
            LobData::String(s) => Ok(s),
            LobData::Bytes(_) => Err(Error::Protocol(
                "Unexpected bytes from CLOB read".to_string(),
            )),
        }
    }

    /// Read a BLOB and return as bytes
    ///
    /// This is a convenience method for reading BLOB data directly as bytes.
    /// Returns an error if the LOB is a CLOB (use read_clob instead).
    pub async fn read_blob(&self, locator: &LobLocator) -> Result<bytes::Bytes> {
        if locator.is_clob() {
            return Err(Error::Protocol(
                "Cannot read CLOB as bytes, use read_clob instead".to_string(),
            ));
        }

        let data = self.read_lob(locator).await?;
        match data {
            LobData::Bytes(b) => Ok(b),
            LobData::String(_) => Err(Error::Protocol(
                "Unexpected string from BLOB read".to_string(),
            )),
        }
    }

    /// Read a LOB in chunks, calling a callback for each chunk
    ///
    /// This is useful for processing large LOBs without loading the entire
    /// content into memory. The callback receives each chunk as it's read.
    ///
    /// # Arguments
    /// * `locator` - The LOB locator
    /// * `chunk_size` - Size of each chunk to read (0 uses the LOB's natural chunk size)
    /// * `callback` - Async function called for each chunk
    ///
    /// # Example
    /// ```ignore
    /// let mut total_size = 0;
    /// conn.read_lob_chunked(&locator, 8192, |chunk| async move {
    ///     match chunk {
    ///         LobData::Bytes(b) => total_size += b.len(),
    ///         LobData::String(s) => total_size += s.len(),
    ///     }
    ///     Ok(())
    /// }).await?;
    /// ```
    pub async fn read_lob_chunked<F, Fut>(
        &self,
        locator: &LobLocator,
        chunk_size: u64,
        mut callback: F,
    ) -> Result<()>
    where
        F: FnMut(LobData) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        self.ensure_ready().await?;

        let total_size = locator.size();
        if total_size == 0 {
            return Ok(());
        }

        // Use LOB's natural chunk size if not specified
        let chunk_size = if chunk_size == 0 {
            self.lob_chunk_size(locator).await?.max(8192) as u64
        } else {
            chunk_size
        };

        let mut offset = 1u64;
        while offset <= total_size {
            let remaining = total_size - offset + 1;
            let amount = std::cmp::min(remaining, chunk_size);

            let chunk = self.read_lob_internal(locator, offset, amount).await?;
            callback(chunk).await?;

            offset += amount;
        }

        Ok(())
    }

    /// Get the optimal chunk size for a LOB
    ///
    /// This returns the chunk size that Oracle recommends for efficient
    /// reading and writing to this LOB.
    pub async fn lob_chunk_size(&self, locator: &LobLocator) -> Result<u32> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create LOB operation message for get chunk size
        let mut lob_msg = LobOpMessage::new_get_chunk_size(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB chunk size response".to_string()));
        }

        // Check for MARKER packet
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse the amount response (chunk size is returned as amount)
        self.parse_lob_amount_response(&response[PACKET_HEADER_SIZE..], locator)
            .map(|v| v as u32)
    }

    /// Internal LOB read implementation
    async fn read_lob_internal(
        &self,
        locator: &LobLocator,
        offset: u64,
        amount: u64,
    ) -> Result<LobData> {
        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let legacy_11g = inner.server_info.protocol_version <= version::MIN_ACCEPTED;

        // Create LOB operation message for read
        let mut lob_msg = LobOpMessage::new_read(locator, offset, amount);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response (may span multiple packets for large LOBs)
        let response = inner
            .receive_lob_response(locator.locator_bytes().len() + 8)
            .await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB read response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            // Skip data flags
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse LOB data response
        let payload = &response[PACKET_HEADER_SIZE..];
        self.parse_lob_read_response(payload, locator, amount, legacy_11g)
    }

    /// Parse LOB read response
    fn parse_lob_read_response(
        &self,
        payload: &[u8],
        locator: &LobLocator,
        _amount: u64,
        legacy_11g: bool,
    ) -> Result<LobData> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut lob_data: Option<Vec<u8>> = None;

        // Process messages until end of response
        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // LobData message (14)
                x if x == MessageType::LobData as u8 => {
                    // Read LOB data with length
                    let data = if legacy_11g {
                        self.read_legacy_11g_lob_data(&mut buf)?
                    } else {
                        buf.read_raw_bytes_chunked()?
                    };
                    lob_data = Some(data);
                }

                // Parameter return (8) - contains updated locator and amount
                x if x == MessageType::Parameter as u8 => {
                    // Skip the updated locator (same length as original)
                    let locator_len = locator.locator_bytes().len();
                    if let Err(e) = buf.skip(locator_len) {
                        if lob_data.is_some() && matches!(e, Error::BufferUnderflow { .. }) {
                            break;
                        }
                        return Err(e);
                    }

                    // Read back the amount (ub8)
                    if let Err(e) = buf.read_ub8() {
                        if lob_data.is_some()
                            && matches!(
                                e,
                                Error::BufferUnderflow { .. } | Error::InvalidLengthIndicator(_)
                            )
                        {
                            break;
                        }
                        return Err(e);
                    }
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    // Parse error info - code 0 means success
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                        // code 0 = success, continue processing
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                // Skip other message types
                _ => {
                    // Try to skip unknown messages
                    continue;
                }
            }
        }

        // Convert to appropriate type based on LOB type
        match lob_data {
            Some(data) => {
                if locator.is_blob() || locator.is_bfile() {
                    Ok(LobData::Bytes(bytes::Bytes::from(data)))
                } else {
                    // CLOB - decode based on encoding
                    let text = if locator.uses_var_length_charset() {
                        // UTF-16 BE encoding
                        let chars: Vec<u16> = data
                            .chunks_exact(2)
                            .map(|c| u16::from_be_bytes([c[0], c[1]]))
                            .collect();
                        String::from_utf16_lossy(&chars)
                    } else {
                        // UTF-8 encoding
                        String::from_utf8_lossy(&data).to_string()
                    };
                    Ok(LobData::String(text))
                }
            }
            None => {
                // Empty LOB
                if locator.is_blob() || locator.is_bfile() {
                    Ok(LobData::Bytes(bytes::Bytes::new()))
                } else {
                    Ok(LobData::String(String::new()))
                }
            }
        }
    }

    fn read_legacy_11g_lob_data(&self, buf: &mut ReadBuffer) -> Result<Vec<u8>> {
        use crate::constants::length;

        let length = buf.read_u8()?;
        if length != length::LONG_INDICATOR {
            return buf.read_bytes_vec(length as usize);
        }

        let mut data = Vec::new();
        loop {
            let chunk_len = buf.read_u8()? as usize;
            if chunk_len == 0 {
                break;
            }
            let chunk = buf.read_bytes_vec(chunk_len)?;
            data.extend_from_slice(&chunk);
        }

        Ok(data)
    }

    /// Write data to a LOB
    ///
    /// # Arguments
    /// * `locator` - The LOB locator obtained from a query result
    /// * `offset` - Starting position (1-based, in characters for CLOB, bytes for BLOB)
    /// * `data` - Data to write (bytes for BLOB, UTF-8 encoded bytes for CLOB)
    pub async fn write_lob(&self, locator: &LobLocator, offset: u64, data: &[u8]) -> Result<()> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let sdu_size = inner.sdu_size as usize;

        // Encode data for CLOB if necessary
        let encoded_data: Vec<u8>;
        let write_data = if locator.is_clob() && locator.uses_var_length_charset() {
            // Convert UTF-8 to UTF-16 BE for CLOB with var length charset
            let text = String::from_utf8_lossy(data);
            encoded_data = text.encode_utf16().flat_map(|c| c.to_be_bytes()).collect();
            &encoded_data[..]
        } else {
            data
        };

        // Create LOB operation message for write
        let mut lob_msg = LobOpMessage::new_write(locator, offset, write_data);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build message content (without packet header or data flags)
        let message = lob_msg.build_message_only(&inner.capabilities)?;

        // Calculate if this fits in a single packet
        // Single packet max payload = SDU - header (8) - data flags (2)
        let max_single_packet_payload = sdu_size.saturating_sub(PACKET_HEADER_SIZE + 2);

        let is_multi_packet = message.len() > max_single_packet_payload;

        if is_multi_packet {
            // Needs multiple packets - use multi-packet sender
            inner.send_multi_packet(&message, 0).await?;
        } else {
            // Fits in one packet - use standard send
            let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
            inner.send(&request).await?;
        }

        // Receive and parse response
        // Use receive_response() to accumulate all packets until END_OF_RESPONSE.
        // This is necessary because Oracle may send multiple packets for the response,
        // and if we only read one packet, leftover data causes close() to hang.
        let response = inner
            .receive_lob_response(locator.locator_bytes().len())
            .await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB write response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse response to check for errors
        self.parse_lob_simple_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Write string data to a CLOB
    pub async fn write_clob(&self, locator: &LobLocator, offset: u64, text: &str) -> Result<()> {
        if locator.is_blob() || locator.is_bfile() {
            return Err(Error::Protocol(
                "Cannot write string to BLOB/BFILE, use write_blob instead".to_string(),
            ));
        }
        self.write_lob(locator, offset, text.as_bytes()).await
    }

    /// Write binary data to a BLOB
    pub async fn write_blob(&self, locator: &LobLocator, offset: u64, data: &[u8]) -> Result<()> {
        if locator.is_clob() {
            return Err(Error::Protocol(
                "Cannot write bytes to CLOB, use write_clob instead".to_string(),
            ));
        }
        self.write_lob(locator, offset, data).await
    }

    /// Get the length of a LOB
    ///
    /// For CLOB: returns length in characters
    /// For BLOB: returns length in bytes
    pub async fn lob_length(&self, locator: &LobLocator) -> Result<u64> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create LOB operation message for get length
        let mut lob_msg = LobOpMessage::new_get_length(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB get_length response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse response to get the length
        self.parse_lob_amount_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Trim a LOB to a specified length
    ///
    /// # Arguments
    /// * `locator` - The LOB locator
    /// * `new_size` - The new size (in characters for CLOB, bytes for BLOB)
    pub async fn lob_trim(&self, locator: &LobLocator, new_size: u64) -> Result<()> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create LOB operation message for trim
        let mut lob_msg = LobOpMessage::new_trim(locator, new_size);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB trim response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse response to check for errors
        self.parse_lob_simple_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Create a temporary LOB on the server
    ///
    /// Creates a temporary LOB of the specified type that lives until the connection
    /// is closed or the LOB is explicitly freed.
    ///
    /// # Arguments
    /// * `oracle_type` - The LOB type to create (Clob or Blob)
    ///
    /// # Returns
    /// A `LobLocator` for the newly created temporary LOB
    ///
    /// # Example
    /// ```ignore
    /// use oracle_rs::OracleType;
    ///
    /// let locator = conn.create_temp_lob(OracleType::Clob).await?;
    /// conn.write_clob(&locator, 1, "Hello, World!").await?;
    /// // Now bind the locator to insert into a CLOB column
    /// ```
    pub async fn create_temp_lob(&self, oracle_type: OracleType) -> Result<LobLocator> {
        use crate::buffer::ReadBuffer;

        // Validate oracle_type is a LOB type
        match oracle_type {
            OracleType::Clob | OracleType::Blob => {}
            _ => {
                return Err(Error::Protocol(format!(
                    "create_temp_lob: invalid type {:?}, must be Clob or Blob",
                    oracle_type
                )));
            }
        }

        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create the CREATE_TEMP message
        let mut lob_msg = LobOpMessage::new_create_temp(oracle_type);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol(
                "Empty CREATE_TEMP LOB response".to_string(),
            ));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse response to extract the locator
        let payload = &response[PACKET_HEADER_SIZE..];
        let mut buf = ReadBuffer::from_slice(payload);
        buf.skip(2)?; // Skip data flags

        let mut locator_bytes: Option<Vec<u8>> = None;

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Parameter return (8) - contains the populated locator
                x if x == MessageType::Parameter as u8 => {
                    // Read the 40-byte locator (matches the 40 bytes sent in request)
                    let loc_data = buf.read_bytes_vec(40)?;
                    locator_bytes = Some(loc_data);
                    // Skip charset (variable-length ub2) and trailing flags (raw u8)
                    buf.skip_ub2()?;
                    buf.skip(1)?;
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message =
                                msg.unwrap_or_else(|| "CREATE_TEMP LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                _ => continue,
            }
        }

        // Create the LobLocator from the returned bytes
        let loc_bytes = locator_bytes.ok_or_else(|| {
            Error::Protocol("CREATE_TEMP LOB response did not contain locator".to_string())
        })?;

        // Create LobLocator with size 0, chunk_size 0 (will be fetched if needed)
        let locator = LobLocator::new(
            bytes::Bytes::from(loc_bytes),
            0, // size - unknown for new temp LOB
            0, // chunk_size - unknown, can be fetched later
            oracle_type,
            1, // csfrm - 1 for CLOB, 0 for BLOB (but we store it on the locator type)
        );

        Ok(locator)
    }

    // ==================== BFILE Operations ====================

    /// Check if a BFILE exists on the server
    ///
    /// Returns true if the file referenced by the BFILE locator exists on the server.
    pub async fn bfile_exists(&self, locator: &LobLocator) -> Result<bool> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_exists called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_exists(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE exists response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        self.parse_lob_bool_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Open a BFILE for reading
    ///
    /// The BFILE must be opened before reading. After reading, close it with bfile_close.
    pub async fn bfile_open(&self, locator: &LobLocator) -> Result<()> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_open called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_open(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE open response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        self.parse_lob_simple_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Close a BFILE after reading
    pub async fn bfile_close(&self, locator: &LobLocator) -> Result<()> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_close called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_close(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE close response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        self.parse_lob_simple_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Check if a BFILE is currently open
    pub async fn bfile_is_open(&self, locator: &LobLocator) -> Result<bool> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_is_open called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_is_open(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE is_open response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        self.parse_lob_bool_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Read BFILE data
    ///
    /// This is a convenience method that opens the BFILE if needed, reads all content,
    /// and returns it as bytes. For large BFILEs, consider using read_lob_chunked.
    pub async fn read_bfile(&self, locator: &LobLocator) -> Result<bytes::Bytes> {
        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "read_bfile called on non-BFILE locator".to_string(),
            ));
        }

        // Check if file is open, open if needed
        let should_close = if !self.bfile_is_open(locator).await? {
            self.bfile_open(locator).await?;
            true
        } else {
            false
        };

        // Read all data
        let result = self.read_blob(locator).await;

        // Close if we opened it
        if should_close {
            let _ = self.bfile_close(locator).await;
        }

        result
    }

    /// Parse a LOB operation response that returns a boolean (file_exists, is_open)
    fn parse_lob_bool_response(&self, payload: &[u8], locator: &LobLocator) -> Result<bool> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::from_slice(payload);
        buf.skip(2)?; // Skip data flags

        let mut bool_result: bool = false;

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Parameter return (8) - contains updated locator and bool flag
                x if x == MessageType::Parameter as u8 => {
                    let locator_len = locator.locator_bytes().len();
                    buf.skip(locator_len)?;
                    // Boolean flag is a single byte, > 0 means true
                    let flag = buf.read_u8()?;
                    bool_result = flag > 0;
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                _ => continue,
            }
        }

        Ok(bool_result)
    }

    /// Parse a simple LOB operation response (write, trim)
    fn parse_lob_simple_response(&self, payload: &[u8], locator: &LobLocator) -> Result<()> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::from_slice(payload);
        buf.skip(2)?; // Skip data flags

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Parameter return (8) - contains updated locator and possibly amount
                x if x == MessageType::Parameter as u8 => {
                    let locator_len = locator.locator_bytes().len();
                    buf.skip(locator_len)?;
                    // After locator, there may be amount (ub8) if send_amount was true
                    // We just skip any remaining bytes until we hit Error or EndOfResponse
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                _ => continue,
            }
        }

        Ok(())
    }

    /// Parse a LOB operation response that returns an amount (get_length, get_chunk_size)
    fn parse_lob_amount_response(&self, payload: &[u8], locator: &LobLocator) -> Result<u64> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::from_slice(payload);
        buf.skip(2)?; // Skip data flags

        let mut returned_amount: u64 = 0;

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                // Parameter return (8) - contains updated locator and amount
                x if x == MessageType::Parameter as u8 => {
                    let locator_len = locator.locator_bytes().len();
                    buf.skip(locator_len)?;
                    returned_amount = buf.read_ub8()?;
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                _ => continue,
            }
        }

        Ok(returned_amount)
    }

    /// Parse LOB error response
    fn parse_lob_error<T>(&self, buf: &mut crate::buffer::ReadBuffer) -> Result<T> {
        // Try to extract error info
        if let Ok((code, msg, _)) = self.parse_error_info(buf) {
            let message = msg.unwrap_or_else(|| "Unknown LOB error".to_string());
            Err(Error::OracleError { code, message })
        } else {
            Err(Error::Protocol("LOB operation failed".to_string()))
        }
    }

    /// Close the connection.
    ///
    /// Sends a logoff message to the server and closes the underlying TCP
    /// connection. After calling close, the connection cannot be reused.
    ///
    /// If the connection is already closed, this method returns `Ok(())`
    /// without doing anything.
    ///
    /// # Note
    ///
    /// Any uncommitted transaction is rolled back by the server when the
    /// connection is closed.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use oracle_rs::{Config, Connection};
    /// # async fn example() -> oracle_rs::Result<()> {
    /// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
    /// let conn = Connection::connect_with_config(config).await?;
    ///
    /// // Do work...
    /// conn.commit().await?;
    ///
    /// // Explicitly close when done
    /// conn.close().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::Relaxed) {
            // Already closed
            return Ok(());
        }

        let mut inner = self.inner.lock().await;

        if inner.state == ConnectionState::Ready {
            // Send logoff
            let _ = self
                .send_simple_function_inner(&mut inner, FunctionCode::Logoff)
                .await;
        }

        inner.state = ConnectionState::Closed;

        // Close the TCP stream
        if let Some(stream) = inner.stream.take() {
            drop(stream);
        }

        Ok(())
    }

    /// Send a marker packet to the server
    /// marker_type: 1=BREAK, 2=RESET, 3=INTERRUPT
    async fn send_marker(&self, inner: &mut ConnectionInner, marker_type: u8) -> Result<()> {
        let mut packet_buf = WriteBuffer::new();

        // Build MARKER packet header
        let packet_len = PACKET_HEADER_SIZE + 3; // Header + 3 bytes payload
        packet_buf.write_u16_be(packet_len as u16)?;
        packet_buf.write_u16_be(0)?; // Checksum
        packet_buf.write_u8(PacketType::Marker as u8)?;
        packet_buf.write_u8(0)?; // Flags
        packet_buf.write_u16_be(0)?; // Header checksum

        // Marker payload: [1, 0, marker_type] per Python's _send_marker
        packet_buf.write_u8(1)?;
        packet_buf.write_u8(0)?;
        packet_buf.write_u8(marker_type)?;

        inner.send(&packet_buf.freeze()).await
    }

    async fn send_simple_function_inner(
        &self,
        inner: &mut ConnectionInner,
        function_code: FunctionCode,
    ) -> Result<()> {
        // Build function message
        let mut buf = WriteBuffer::new();

        // Get next sequence number (must be done before sending)
        let seq_num = inner.next_sequence_number();

        // Data flags
        buf.write_u16_be(0)?;
        // Message type: Function
        buf.write_u8(MessageType::Function as u8)?;
        // Function code
        buf.write_u8(function_code as u8)?;
        // Sequence number (tracked per connection)
        buf.write_u8(seq_num)?;

        // Token number (required for TTC field version >= 18, i.e. Oracle 23ai)
        if inner.capabilities.ttc_field_version >= 18 {
            buf.write_ub8(0)?;
        }

        // Build DATA packet
        let data_payload = buf.freeze();
        let mut packet_buf = WriteBuffer::new();
        let packet_len = PACKET_HEADER_SIZE + data_payload.len();
        packet_buf.write_u16_be(packet_len as u16)?;
        packet_buf.write_u16_be(0)?; // Checksum
        packet_buf.write_u8(PacketType::Data as u8)?;
        packet_buf.write_u8(0)?; // Flags
        packet_buf.write_u16_be(0)?; // Header checksum
        packet_buf.write_bytes(&data_payload)?;

        let packet_bytes = packet_buf.freeze();
        inner.send(&packet_bytes).await?;

        // Wait for response
        let response = inner.receive().await?;

        // Check response
        if response.len() <= 4 {
            return Err(Error::Protocol("Response too short".to_string()));
        }

        let packet_type = response[4];

        // MARKER packet (type 12) - need to handle reset protocol
        if packet_type == PacketType::Marker as u8 {
            // Check marker type
            if response.len() >= PACKET_HEADER_SIZE + 3 {
                let marker_type = response[PACKET_HEADER_SIZE + 2];

                // For BREAK marker (1), we need to do the reset protocol
                if marker_type == 1 {
                    // For Logoff, Oracle may send BREAK to indicate "connection closing"
                    // Don't try to do the full reset handshake - just return success
                    if function_code == FunctionCode::Logoff {
                        inner.state = ConnectionState::Closed;
                        return Ok(());
                    }

                    // The BREAK marker means the server is interrupting/breaking the current operation
                    // We MUST complete the reset handshake or the connection will be in a bad state

                    // Send RESET marker to server
                    if let Err(e) = self.send_marker(inner, 2).await {
                        inner.state = ConnectionState::Closed;
                        return Err(e);
                    }

                    // Read and discard packets until we get RESET marker
                    // This follows Python's _reset() logic
                    let mut current_packet_type: u8;
                    loop {
                        match inner.receive().await {
                            Ok(pkt) => {
                                if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                    break;
                                }
                                current_packet_type = pkt[4];

                                if current_packet_type == PacketType::Marker as u8 {
                                    if pkt.len() >= PACKET_HEADER_SIZE + 3 {
                                        let mk_type = pkt[PACKET_HEADER_SIZE + 2];
                                        if mk_type == 2 {
                                            // Got RESET marker, exit this loop
                                            break;
                                        }
                                    }
                                } else {
                                    // Non-marker packet - unexpected during reset wait
                                    break;
                                }
                            }
                            Err(e) => {
                                inner.state = ConnectionState::Closed;
                                return Err(e);
                            }
                        }
                    }

                    // After RESET, continue reading while we still get MARKER packets
                    // Some servers send multiple RESET markers, others send DATA response
                    // Python comment: "some quit immediately" - meaning some servers close
                    // the connection right after the reset handshake
                    loop {
                        match inner.receive().await {
                            Ok(pkt) => {
                                if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                    break;
                                }
                                current_packet_type = pkt[4];

                                if current_packet_type == PacketType::Marker as u8 {
                                    // Another marker, continue reading
                                    continue;
                                }

                                // Got a non-marker packet (probably DATA with error/status)
                                if current_packet_type == PacketType::Data as u8
                                    && pkt.len() > PACKET_HEADER_SIZE + 2
                                {
                                    let msg_type = pkt[PACKET_HEADER_SIZE + 2];
                                    if msg_type == MessageType::Error as u8 {
                                        let payload = &pkt[PACKET_HEADER_SIZE..];
                                        let mut buf = ReadBuffer::from_slice(payload);
                                        buf.skip(2)?; // data flags
                                        buf.skip(1)?; // msg_type
                                        let (error_code, error_msg, _) =
                                            self.parse_error_info(&mut buf)?;
                                        if error_code != 0 {
                                            return Err(Error::OracleError {
                                                code: error_code,
                                                message: error_msg.unwrap_or_else(|| {
                                                    format!("ORA-{:05}", error_code)
                                                }),
                                            });
                                        }
                                    }
                                }
                                // Exit after processing non-marker packet
                                break;
                            }
                            Err(_) => {
                                // Error reading - connection might be closed
                                // Python comment says "some quit immediately" - meaning some
                                // servers close the connection after BREAK/RESET handshake.
                                // For commit/rollback/logoff, treat this as success since
                                // the operation was processed before the close.
                                if matches!(
                                    function_code,
                                    FunctionCode::Logoff
                                        | FunctionCode::Commit
                                        | FunctionCode::Rollback
                                ) {
                                    // The operation succeeded, but the server closed the connection
                                    // Mark connection as closed for future operations
                                    inner.state = ConnectionState::Closed;
                                    return Ok(());
                                }
                                // For other functions, this means connection is broken
                                inner.state = ConnectionState::Closed;
                                // Don't return error for Ping - treat as success
                                if function_code == FunctionCode::Ping {
                                    return Ok(());
                                }
                                return Ok(()); // Conservative approach - treat as success
                            }
                        }
                    }

                    return Ok(());
                }
            }
            // For non-BREAK markers, just return success
            return Ok(());
        }

        // DATA packet (type 6)
        if packet_type == PacketType::Data as u8 {
            // Parse response to check for errors
            if response.len() > PACKET_HEADER_SIZE + 2 {
                let msg_type = response[PACKET_HEADER_SIZE + 2];
                if msg_type == MessageType::Error as u8 {
                    // Parse the error info
                    let payload = &response[PACKET_HEADER_SIZE..];
                    let mut buf = ReadBuffer::from_slice(payload);
                    buf.skip(2)?; // data flags
                    buf.skip(1)?; // msg_type
                    let (error_code, error_msg, _) = self.parse_error_info(&mut buf)?;
                    if error_code != 0 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_else(|| format!("ORA-{:05}", error_code)),
                        });
                    }
                }
            }
            return Ok(());
        }

        Err(Error::Protocol(format!(
            "Unexpected packet type {} for function call",
            packet_type
        )))
    }

    /// Ensure the connection is ready for operations
    async fn ensure_ready(&self) -> Result<()> {
        if self.is_closed() {
            return Err(Error::ConnectionClosed);
        }

        let inner = self.inner.lock().await;
        if inner.state != ConnectionState::Ready {
            return Err(Error::ConnectionNotReady);
        }

        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Note: Can't do async cleanup in Drop
        // Users should call close() explicitly
        self.closed.store(true, Ordering::Relaxed);
    }
}

// =============================================================================
// Helper functions for get_type()
// =============================================================================

/// Parse a type name into (schema, name) components
///
/// Handles formats like:
/// - "SCHEMA.TYPE_NAME" -> ("SCHEMA", "TYPE_NAME")
/// - "TYPE_NAME" -> (default_schema, "TYPE_NAME")
fn parse_type_name(type_name: &str, default_schema: &str) -> (String, String) {
    let parts: Vec<&str> = type_name.split('.').collect();
    match parts.len() {
        1 => (default_schema.to_uppercase(), parts[0].to_uppercase()),
        2 => (parts[0].to_uppercase(), parts[1].to_uppercase()),
        _ => {
            // Multiple dots - take first as schema, rest as name
            (parts[0].to_uppercase(), parts[1..].join(".").to_uppercase())
        }
    }
}

/// Convert an Oracle type name from data dictionary to OracleType enum
fn oracle_type_from_name(type_name: &str) -> crate::constants::OracleType {
    use crate::constants::OracleType;

    match type_name.to_uppercase().as_str() {
        "NUMBER" => OracleType::Number,
        "INTEGER" | "INT" | "SMALLINT" => OracleType::Number,
        "FLOAT" | "REAL" | "DOUBLE PRECISION" => OracleType::BinaryDouble,
        "BINARY_FLOAT" => OracleType::BinaryFloat,
        "BINARY_DOUBLE" => OracleType::BinaryDouble,
        "VARCHAR2" | "VARCHAR" | "NVARCHAR2" => OracleType::Varchar,
        "CHAR" | "NCHAR" => OracleType::Char,
        "DATE" => OracleType::Date,
        "TIMESTAMP" => OracleType::Timestamp,
        "TIMESTAMP WITH TIME ZONE" => OracleType::TimestampTz,
        "TIMESTAMP WITH LOCAL TIME ZONE" => OracleType::TimestampLtz,
        "RAW" => OracleType::Raw,
        "BLOB" => OracleType::Blob,
        "CLOB" | "NCLOB" => OracleType::Clob,
        "BOOLEAN" | "PL/SQL BOOLEAN" => OracleType::Boolean,
        "ROWID" | "UROWID" => OracleType::Rowid,
        "XMLTYPE" => OracleType::Varchar, // Treat XMLType as string for now
        _ => OracleType::Varchar,         // Default to VARCHAR for unknown types
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::row::Value;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn make_test_connection() -> Connection {
        Connection {
            inner: Arc::new(Mutex::new(ConnectionInner::new_with_cache(0))),
            config: Config::new(
                "localhost".to_string(),
                1521,
                "xe".to_string(),
                "user".to_string(),
                "password".to_string(),
            ),
            closed: AtomicBool::new(false),
            id: 1,
        }
    }

    #[test]
    fn test_query_options_default() {
        let opts = QueryOptions::default();
        assert_eq!(opts.prefetch_rows, 100);
        assert_eq!(opts.array_size, 100);
        assert!(!opts.auto_commit);
    }

    #[test]
    fn test_query_result_empty() {
        let result = QueryResult::empty();
        assert!(result.is_empty());
        assert_eq!(result.column_count(), 0);
        assert_eq!(result.row_count(), 0);
        assert!(result.first().is_none());
    }

    #[test]
    fn test_query_result_with_rows() {
        let columns = vec![ColumnInfo::new("ID", crate::constants::OracleType::Number)];
        let rows = vec![Row::new(vec![Value::Integer(1)])];

        let result = QueryResult {
            columns,
            rows,
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 1,
        };

        assert!(!result.is_empty());
        assert_eq!(result.column_count(), 1);
        assert_eq!(result.row_count(), 1);
        assert!(result.first().is_some());
        assert!(result.column_by_name("ID").is_some());
        assert!(result.column_by_name("id").is_some()); // Case insensitive
        assert_eq!(result.column_index("ID"), Some(0));
    }

    #[test]
    fn test_server_info_default() {
        let info = ServerInfo::default();
        assert!(info.version.is_empty());
        assert_eq!(info.session_id, 0);
    }

    #[test]
    fn test_connection_state_transitions() {
        assert_eq!(ConnectionState::Disconnected, ConnectionState::Disconnected);
        assert_ne!(ConnectionState::Connected, ConnectionState::Ready);
    }

    #[test]
    fn test_inspect_message_stream_lob_parameter_is_complete() {
        let inner = ConnectionInner::new_with_cache(0);
        let data = [
            MessageType::LobData as u8,
            3,
            b'a',
            b'b',
            b'c',
            MessageType::Parameter as u8,
        ];

        assert_eq!(inner.inspect_message_stream(&data), (false, false));
    }

    #[test]
    fn test_inspect_message_stream_legacy_11g_lob_chunks_are_complete() {
        let mut inner = ConnectionInner::new_with_cache(0);
        inner.server_info.protocol_version = 314;
        let mut data = vec![
            MessageType::LobData as u8,
            crate::constants::length::LONG_INDICATOR,
            crate::constants::length::MAX_SHORT,
        ];
        data.extend(std::iter::repeat(b'a').take(crate::constants::length::MAX_SHORT as usize));
        data.push(1);
        data.push(b'b');
        data.push(0);
        data.push(MessageType::Parameter as u8);

        assert_eq!(inner.inspect_message_stream(&data), (false, false));
    }

    #[test]
    fn test_inspect_message_stream_legacy_11g_lob_truncated_chunk_is_incomplete() {
        let mut inner = ConnectionInner::new_with_cache(0);
        inner.server_info.protocol_version = 314;
        let data = [
            MessageType::LobData as u8,
            crate::constants::length::LONG_INDICATOR,
            4,
            b'a',
            b'b',
        ];

        assert_eq!(inner.inspect_message_stream(&data), (false, true));
    }

    #[test]
    fn test_inspect_message_stream_legacy_11g_split_lob_parameter_is_incomplete() {
        let mut inner = ConnectionInner::new_with_cache(0);
        inner.server_info.protocol_version = 314;
        let data = [
            MessageType::LobData as u8,
            crate::constants::length::LONG_INDICATOR,
            1,
            b'a',
            0,
            MessageType::Parameter as u8,
            0,
            1,
        ];

        assert_eq!(
            inner.inspect_message_stream_with_lob_parameter_len(&data, Some(4)),
            (false, true)
        );
    }

    #[test]
    fn test_inspect_message_stream_legacy_11g_lob_parameter_then_status_is_complete() {
        let mut inner = ConnectionInner::new_with_cache(0);
        inner.server_info.protocol_version = 314;
        let data = [
            MessageType::LobData as u8,
            crate::constants::length::LONG_INDICATOR,
            1,
            b'a',
            0,
            MessageType::Parameter as u8,
            0,
            1,
            2,
            3,
            MessageType::Status as u8,
        ];

        assert_eq!(
            inner.inspect_message_stream_with_lob_parameter_len(&data, Some(4)),
            (false, false)
        );
    }

    #[test]
    fn test_scan_fetch_stream_status_is_terminal() {
        let conn = make_test_connection();
        let caps = Capabilities::default();
        let cols = vec![ColumnInfo::new("ID", OracleType::Number)];
        let mut state = FetchScanState::default();

        assert_eq!(
            conn.scan_fetch_message_stream(&[MessageType::Status as u8], &cols, &caps, &mut state),
            FetchScanOutcome::Terminal
        );
    }

    #[test]
    fn test_scan_fetch_stream_unknown_message_falls_back() {
        let conn = make_test_connection();
        let caps = Capabilities::default();
        let cols = vec![ColumnInfo::new("ID", OracleType::Number)];
        let mut state = FetchScanState::default();

        assert_eq!(
            conn.scan_fetch_message_stream(
                &[MessageType::Parameter as u8, 1, 2, 3],
                &cols,
                &caps,
                &mut state
            ),
            FetchScanOutcome::Unknown
        );
    }

    #[test]
    fn test_scan_fetch_stream_split_row_resumes_and_terminates_on_error_message() {
        let conn = make_test_connection();
        let caps = Capabilities::default();
        let cols = vec![ColumnInfo::new("ID", OracleType::Number)];
        let mut state = FetchScanState::default();

        // RowData for one NUMBER column (value 1 = c1 02), truncated after
        // the first value byte: provably mid-message.
        let mut data = vec![MessageType::RowData as u8, 2, 0xc1];
        assert_eq!(
            conn.scan_fetch_message_stream(&data, &cols, &caps, &mut state),
            FetchScanOutcome::NeedMore
        );
        assert_eq!(state.scan_offset, 0);

        // Complete the row: all messages parse, but the terminal Error
        // message has not arrived yet, so the response is still incomplete.
        data.push(0x02);
        assert_eq!(
            conn.scan_fetch_message_stream(&data, &cols, &caps, &mut state),
            FetchScanOutcome::NeedMore
        );
        assert_eq!(state.scan_offset, data.len());

        // Append a zero-filled Error message (call status 0, error 0): the
        // terminal message completes the response.
        data.push(MessageType::Error as u8);
        data.extend(std::iter::repeat(0u8).take(48));
        assert_eq!(
            conn.scan_fetch_message_stream(&data, &cols, &caps, &mut state),
            FetchScanOutcome::Terminal
        );
    }

    #[test]
    fn test_scan_fetch_stream_bit_vector_changes_row_width() {
        let conn = make_test_connection();
        let caps = Capabilities::default();
        let cols = vec![
            ColumnInfo::new("A", OracleType::Number),
            ColumnInfo::new("B", OracleType::Number),
        ];
        let mut state = FetchScanState::default();

        // BitVector: 2 columns sent (ub2 = [1, 2]), bit 0 set / bit 1 clear,
        // so the following RowData carries only column A; column B is a
        // duplicate and consumes no bytes. Status terminates the stream.
        let data = vec![
            MessageType::BitVector as u8,
            1,
            2,
            0b0000_0001,
            MessageType::RowData as u8,
            2,
            0xc1,
            0x02,
            MessageType::Status as u8,
        ];
        assert_eq!(
            conn.scan_fetch_message_stream(&data, &cols, &caps, &mut state),
            FetchScanOutcome::Terminal
        );
    }

    #[test]
    fn test_scan_fetch_stream_truncated_error_message_needs_more() {
        let conn = make_test_connection();
        let caps = Capabilities::default();
        let cols = vec![ColumnInfo::new("ID", OracleType::Number)];
        let mut state = FetchScanState::default();

        // Error message truncated a few fields in: the terminal message
        // itself is split across packets, so the response is not complete.
        assert_eq!(
            conn.scan_fetch_message_stream(
                &[MessageType::Error as u8, 0, 0, 0],
                &cols,
                &caps,
                &mut state
            ),
            FetchScanOutcome::NeedMore
        );
    }

    #[test]
    fn test_parse_legacy_11g_lob_read_preserves_multibyte_clob_chunk() {
        let conn = make_test_connection();
        let locator = LobLocator::new(Bytes::from(vec![0; 20]), 2, 0, OracleType::Clob, 1);
        let payload = [
            0,
            0,
            MessageType::LobData as u8,
            crate::constants::length::LONG_INDICATOR,
            4,
            0xc3,
            0xa9,
            0xc3,
            0xa9,
            0,
            MessageType::EndOfResponse as u8,
        ];

        let data = conn
            .parse_lob_read_response(&payload, &locator, 2, true)
            .unwrap();

        match data {
            LobData::String(text) => assert_eq!(text.as_bytes(), &[0xc3, 0xa9, 0xc3, 0xa9]),
            other => panic!("Expected CLOB string, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_error_info_legacy_11g_short_layout() {
        let conn = make_test_connection();
        let mut payload = WriteBuffer::new();

        payload.write_ub4(0).unwrap(); // call status
        payload.write_ub2(0).unwrap(); // end-to-end sequence
        payload.write_ub4(0).unwrap(); // current row number
        payload.write_ub2(942).unwrap(); // short error number
        payload.write_ub2(0).unwrap(); // array elem error
        payload.write_ub2(0).unwrap(); // array elem error
        payload.write_ub2(7).unwrap(); // cursor id
        payload.write_ub2(0).unwrap(); // error position
        payload.write_u8(0).unwrap(); // sql type
        payload.write_u8(0).unwrap(); // fatal
        payload.write_u8(0).unwrap(); // flags
        payload.write_u8(0).unwrap(); // user cursor options
        payload.write_u8(0).unwrap(); // UPI parameter
        payload.write_u8(0).unwrap(); // second flags
        payload.write_ub4(0).unwrap(); // rowid rba
        payload.write_ub2(0).unwrap(); // rowid partition
        payload.write_u8(0).unwrap(); // rowid skip
        payload.write_ub4(0).unwrap(); // rowid block
        payload.write_ub2(0).unwrap(); // rowid slot
        payload.write_ub4(0).unwrap(); // OS error
        payload.write_u8(0).unwrap(); // statement number
        payload.write_u8(0).unwrap(); // call number
        payload.write_ub2(0).unwrap(); // padding
        payload.write_ub4(0).unwrap(); // success iters
        payload.write_ub4(0).unwrap(); // logical rowid length
        payload.write_ub2(0).unwrap(); // batch error count
        payload.write_ub4(0).unwrap(); // batch offset count
        payload.write_ub2(0).unwrap(); // batch message count
        payload
            .write_string_with_length(Some("ORA-00942: table or view does not exist\n"))
            .unwrap();

        let bytes = payload.freeze();
        let mut buf = ReadBuffer::from_slice(&bytes);
        let (code, message, cursor_id) = conn.parse_error_info(&mut buf).unwrap();

        assert_eq!(code, 942);
        assert_eq!(cursor_id, 7);
        assert_eq!(
            message.as_deref(),
            Some("ORA-00942: table or view does not exist")
        );
    }

    #[test]
    fn test_parse_fetch_error_info_legacy_11g_short_layout() {
        let conn = make_test_connection();
        let mut payload = WriteBuffer::new();

        payload.write_ub4(0).unwrap(); // call status
        payload.write_ub2(0).unwrap(); // end-to-end sequence
        payload.write_ub4(0).unwrap(); // current row number
        payload.write_ub2(1403).unwrap(); // short error number
        payload.write_ub2(0).unwrap(); // array elem error
        payload.write_ub2(0).unwrap(); // array elem error
        payload.write_ub2(7).unwrap(); // cursor id
        payload.write_ub2(0).unwrap(); // error position
        payload.write_u8(0).unwrap(); // sql type
        payload.write_u8(0).unwrap(); // fatal
        payload.write_u8(0).unwrap(); // flags
        payload.write_u8(0).unwrap(); // user cursor options
        payload.write_u8(0).unwrap(); // UPI parameter
        payload.write_u8(0).unwrap(); // second flags
        payload.write_ub4(0).unwrap(); // rowid rba
        payload.write_ub2(0).unwrap(); // rowid partition
        payload.write_u8(0).unwrap(); // rowid skip
        payload.write_ub4(0).unwrap(); // rowid block
        payload.write_ub2(0).unwrap(); // rowid slot
        payload.write_ub4(0).unwrap(); // OS error
        payload.write_u8(0).unwrap(); // statement number
        payload.write_u8(0).unwrap(); // call number
        payload.write_ub2(0).unwrap(); // padding
        payload.write_ub4(0).unwrap(); // success iters
        payload.write_ub4(0).unwrap(); // logical rowid length
        payload.write_ub2(0).unwrap(); // batch error count
        payload.write_ub4(0).unwrap(); // batch offset count
        payload.write_ub2(0).unwrap(); // batch message count
        payload
            .write_string_with_length(Some("ORA-01403: no data found\n"))
            .unwrap();

        let bytes = payload.freeze();
        let mut buf = ReadBuffer::from_slice(&bytes);
        let (code, message, cursor_id, more_rows) = conn
            .parse_error_message_info(&mut buf, crate::constants::ccap_value::FIELD_VERSION_11_2)
            .unwrap();

        assert_eq!(code, 1403);
        assert_eq!(cursor_id, 7);
        assert!(!more_rows);
        assert_eq!(message, "ORA-01403: no data found");
    }

    #[test]
    fn test_parse_legacy_11g_query_response_from_capture() {
        let conn = make_test_connection();
        let mut caps = Capabilities::new();
        caps.ttc_field_version = crate::constants::ccap_value::FIELD_VERSION_11_2;
        let payload = hex::decode(
            "0000101700000017e75ddbb9ab3c0d227d53bda738ea01787e0401082a030200000001000000510200008102000000000000000000000000000000000000000000000000010101000000013100000000000000000000000000000700000007787e04010b142300000000e81f0000020000000200000000000000062201000000000002000000000000000000000000000702c10208060053480600000000000200000000000000000000000000000000000100000000000b0000000b80000000453c3c80000000a3000000000004010000000400010000007b050000000002000e00030000000000000000000000000000000000000000000000030000010000000000000000000000000000000000194f52412d30313430333a206e6f206461746120666f756e640a",
        )
        .unwrap();

        let result = conn.parse_query_response(&payload, &caps).unwrap();

        assert_eq!(result.columns.len(), 1);
        assert_eq!(result.columns[0].name, "1");
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0].get_string(0), Some("1"));
    }

    #[test]
    fn test_query_result_iterator() {
        let rows = vec![
            Row::new(vec![Value::Integer(1)]),
            Row::new(vec![Value::Integer(2)]),
        ];
        let result = QueryResult {
            columns: vec![],
            rows,
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 0,
        };

        let collected: Vec<_> = result.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_query_result_into_iterator() {
        let rows = vec![
            Row::new(vec![Value::Integer(1)]),
            Row::new(vec![Value::Integer(2)]),
        ];
        let result = QueryResult {
            columns: vec![],
            rows,
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 0,
        };

        let collected: Vec<Row> = result.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }
}
