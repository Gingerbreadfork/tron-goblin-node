//! One-byte message type tag.
//!
//! Mirrors `org.tron.core.net.message.MessageTypes`. The discriminant of
//! each variant **must** match java-tron exactly — these bytes are what
//! travel on the wire, and a mismatch makes the node invisible to the
//! rest of the network.
//!
//! Note the gaps in the enum (no 0x0a..0x0f, no 0x15..0x1f, no 0x24..0x2f,
//! no 0x35..0xfe). These are reserved space in java-tron and not "unused"
//! — a future version could fill them, so we reject unknown values
//! explicitly instead of silently mapping them to `Unknown`.

/// Type-tag byte for a TRON wire message.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MessageType {
    // --- Tron-domain range (0x00..=0x14) -------------------------------
    First = 0x00,
    Trx = 0x01,
    Block = 0x02,
    Trxs = 0x03,
    Blocks = 0x04,
    BlockHeaders = 0x05,
    Inventory = 0x06,
    FetchInvData = 0x07,
    SyncBlockChain = 0x08,
    BlockChainInventory = 0x09,
    ItemNotFound = 0x10,
    FetchBlockHeaders = 0x11,
    BlockInventory = 0x12,
    TrxInventory = 0x13,
    PbftCommitMsg = 0x14,
    // --- P2P-control range (0x20..=0x23) -------------------------------
    P2pHello = 0x20,
    P2pDisconnect = 0x21,
    P2pPing = 0x22,
    P2pPong = 0x23,
    // --- Discovery range (0x30..=0x33) ---------------------------------
    DiscoverPing = 0x30,
    DiscoverPong = 0x31,
    DiscoverFindPeer = 0x32,
    DiscoverPeers = 0x33,
    // --- PBFT range (0x34) ---------------------------------------------
    PbftMsg = 0x34,
    // --- libp2p connection-layer range (0xfb..=0xff) -------------------
    //
    // These wrap the TRON-application messages above on every peer
    // connection. Source: `org.tron.p2p.connection.message.MessageType`
    // in https://github.com/tronprotocol/libp2p. They share the same
    // wire format (varint length-prefix + type byte + payload).
    //
    // The very first frame on a freshly-opened TCP connection must be
    // `Libp2pHandshakeHello` (0xfd) carrying a `Connect.HelloMessage`;
    // application-level `P2pHello` (0x20) is rejected by mainnet peers
    // until that exchange completes.
    Libp2pDisconnect = 0xfb,
    Libp2pStatus = 0xfc,
    Libp2pHandshakeHello = 0xfd,
    Libp2pKeepAlivePong = 0xfe,
    Libp2pKeepAlivePing = 0xff,
}

impl MessageType {
    /// The raw byte that goes on the wire.
    #[inline]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Decode a byte. Rejects values that don't map to a defined variant —
    /// java-tron's `MessageTypes.fromByte` returns `null` for unknown bytes
    /// and most callers treat that as a protocol error.
    pub fn from_byte(b: u8) -> Result<Self, MessageTypeError> {
        Ok(match b {
            0x00 => Self::First,
            0x01 => Self::Trx,
            0x02 => Self::Block,
            0x03 => Self::Trxs,
            0x04 => Self::Blocks,
            0x05 => Self::BlockHeaders,
            0x06 => Self::Inventory,
            0x07 => Self::FetchInvData,
            0x08 => Self::SyncBlockChain,
            0x09 => Self::BlockChainInventory,
            0x10 => Self::ItemNotFound,
            0x11 => Self::FetchBlockHeaders,
            0x12 => Self::BlockInventory,
            0x13 => Self::TrxInventory,
            0x14 => Self::PbftCommitMsg,
            0x20 => Self::P2pHello,
            0x21 => Self::P2pDisconnect,
            0x22 => Self::P2pPing,
            0x23 => Self::P2pPong,
            0x30 => Self::DiscoverPing,
            0x31 => Self::DiscoverPong,
            0x32 => Self::DiscoverFindPeer,
            0x33 => Self::DiscoverPeers,
            0x34 => Self::PbftMsg,
            0xfb => Self::Libp2pDisconnect,
            0xfc => Self::Libp2pStatus,
            0xfd => Self::Libp2pHandshakeHello,
            0xfe => Self::Libp2pKeepAlivePong,
            0xff => Self::Libp2pKeepAlivePing,
            other => return Err(MessageTypeError::UnknownByte(other)),
        })
    }

    /// True for P2P-control messages (Hello / Disconnect / Ping / Pong).
    /// Matches `MessageTypes.inP2pRange`.
    #[inline]
    pub fn is_p2p(self) -> bool {
        let b = self.as_byte();
        b >= Self::P2pHello.as_byte() && b <= Self::P2pPong.as_byte()
    }

    /// True for Tron-domain messages (Trx, Block, sync, inventory).
    /// Matches `MessageTypes.inTronRange`.
    #[inline]
    pub fn is_tron(self) -> bool {
        let b = self.as_byte();
        b >= Self::First.as_byte() && b <= Self::PbftCommitMsg.as_byte()
    }

    /// True for PBFT-consensus messages. Matches `MessageTypes.inPbftRange`.
    #[inline]
    pub fn is_pbft(self) -> bool {
        self == Self::PbftMsg
    }

    /// True for the discovery (UDP) sub-protocol.
    #[inline]
    pub fn is_discover(self) -> bool {
        let b = self.as_byte();
        b >= Self::DiscoverPing.as_byte() && b <= Self::DiscoverPeers.as_byte()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MessageTypeError {
    #[error("unknown message type byte: 0x{0:02x}")]
    UnknownByte(u8),
}
