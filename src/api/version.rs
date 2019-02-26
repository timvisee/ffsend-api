use std::fmt;

use version_compare::{CompOp, VersionCompare};

/// Firefox Send version selector.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Version {
    /// Firefox Send v2.
    #[cfg(feature = "send2")]
    V2,

    /// Firefox Send v3.
    #[cfg(feature = "send3")]
    V3,
}

impl Version {
    /// Attempt to parse the API version from a version number string.
    ///
    /// If the given version number string could not be matched to a known
    /// (or not compiled due to a missing compiler feature) API version an
    /// `Err` is returning holding the version string.
    pub fn parse<'a>(ver: &'a str) -> Result<Self, &'a str> {
        // Is this using version 2
        #[cfg(feature = "send2")]
        {
            // Test the lower and upper version bounds
            let lower = VersionCompare::compare_to(ver, "2.0", &CompOp::Ge).map_err(|_| ver)?;
            let upper = VersionCompare::compare_to(ver, "3.0", &CompOp::Lt).map_err(|_| ver)?;
            if lower && upper {
                return Ok(Version::V2);
            }
        }

        // Is this using version 3
        #[cfg(feature = "send3")]
        {
            // Test the lower and upper version bounds
            let lower = VersionCompare::compare_to(ver, "3.0", &CompOp::Ge).map_err(|_| ver)?;
            let upper = VersionCompare::compare_to(ver, "4.0", &CompOp::Lt).map_err(|_| ver)?;
            if lower && upper {
                return Ok(Version::V3);
            }
        }

        Err(ver)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "send2")]
            Version::V2 => write!(f, "2"),

            #[cfg(feature = "send3")]
            Version::V3 => write!(f, "3"),
        }
    }
}
