//! Online anomaly detection — streaming detectors that emit findings as
//! observations arrive.

pub mod detector;
pub mod threshold;
pub mod zscore;

pub use detector::{Anomaly, Detector, DetectorRegistry, Severity};
pub use threshold::ThresholdDetector;
pub use zscore::ZScoreDetector;
