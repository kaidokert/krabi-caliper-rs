//! Common outcome and error types for architecture footprint lifecycles.

#[cfg(feature = "stack")]
use crate::stack::StackError;

/// Failure to acquire or report a target footprint measurement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FootprintError<E> {
    /// The architecture counter required by the lifecycle is unavailable.
    CounterUnavailable,
    /// The target stack could not be painted safely.
    #[cfg(feature = "stack")]
    Stack(StackError),
    /// The selected target reporter rejected an event.
    Reporter(E),
}
