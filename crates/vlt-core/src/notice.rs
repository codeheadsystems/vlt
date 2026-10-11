//! Notices: events a device reports in the status line and lists in `vlt status`, which are not
//! errors. Each names the writer the offending header or index claims, where there is one.

/// Which of the two mutable objects a notice concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// The header.
    Header,
    /// The index.
    Index,
}

/// One notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// An accepted header changed the epoch: "the vault key was changed by <writer>".
    VaultKeyChanged {
        /// The header's writer.
        writer: [u8; 16],
        /// The new epoch.
        epoch: u32,
    },
    /// An accepted header or index advanced its counter more than 2^32 past the pin.
    CounterJump {
        /// Header or index.
        kind: ObjectKind,
        /// Its writer.
        writer: [u8; 16],
        /// The pinned value.
        from: u64,
        /// The accepted value.
        to: u64,
    },
    /// A header whose writer was not enrolled in the previously accepted header, or an index whose
    /// writer is not enrolled in the current header.
    UnenrolledWriter {
        /// Header or index.
        kind: ObjectKind,
        /// Its writer.
        writer: [u8; 16],
    },
    /// A header or index names this device as writer, and this device's records do not reach
    /// back far enough to confirm or deny it.
    OwnWriteUnverified {
        /// Header or index.
        kind: ObjectKind,
        /// Its sequence number.
        seq: u64,
    },
    /// An accepted index's applied table was at or past this device's next `op_seq`, so the
    /// device raised the counter and renumbered its queue.
    OpSeqRaised {
        /// The index's writer.
        writer: [u8; 16],
        /// The new next `op_seq`.
        next_op_seq: u64,
    },
}

impl Notice {
    /// The writer the notice names, if any.
    pub fn writer(&self) -> Option<[u8; 16]> {
        match self {
            Notice::VaultKeyChanged { writer, .. }
            | Notice::CounterJump { writer, .. }
            | Notice::UnenrolledWriter { writer, .. }
            | Notice::OpSeqRaised { writer, .. } => Some(*writer),
            Notice::OwnWriteUnverified { .. } => None,
        }
    }
}
