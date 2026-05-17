//! Service Level Objectives — definitions, error budgets, and the
//! multi-window multi-burn-rate alert evaluator.

pub mod budget;
pub mod definition;
pub mod evaluator;

pub use budget::ErrorBudget;
pub use definition::{Sli, SloConfig, SloWindow};
pub use evaluator::{AlertSeverity, BurnRateTier, MwmbrEvaluator, SloAlert, SloEvaluation};
