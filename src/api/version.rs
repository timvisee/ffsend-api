/// Firefox Send version selector.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Version {
    /// Firefox Send v1.
    #[cfg(feature = "send1")]
    V1,

    /// Firefox Send v2.
    #[cfg(feature = "send2")]
    V2,
}
