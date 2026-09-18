use std::pin::Pin;
use std::sync::Arc;

use futures::StreamExt;
use pyo3::prelude::*;
use tokio::sync::Mutex;

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One network-policy enforcement event.
#[pyclass(name = "NetworkDecision")]
pub struct PyNetworkDecision {
    #[pyo3(get)]
    pub sequence: u64,
    #[pyo3(get)]
    pub timestamp: String,
    #[pyo3(get)]
    pub phase: String,
    #[pyo3(get)]
    pub action: String,
    #[pyo3(get)]
    pub reason: String,
    #[pyo3(get)]
    pub destination_host: Option<String>,
    #[pyo3(get)]
    pub destination_ip: Option<String>,
    #[pyo3(get)]
    pub destination_port: Option<u16>,
    #[pyo3(get)]
    pub transport: String,
    #[pyo3(get)]
    pub protocol: Option<String>,
    #[pyo3(get)]
    pub sni: Option<String>,
    #[pyo3(get)]
    pub http_authority: Option<String>,
    #[pyo3(get)]
    pub correlation_id: Option<String>,
    #[pyo3(get)]
    pub matched_rule: Option<String>,
    #[pyo3(get)]
    pub dropped_count: u64,
    #[pyo3(get)]
    pub earliest_retained_sequence: u64,
}

type DecisionStreamInner = Pin<
    Box<
        dyn futures::Stream<
                Item = microsandbox::MicrosandboxResult<microsandbox::NetworkDecisionItem>,
            > + Send,
    >,
>;

/// Async iterator over network-policy decisions.
#[pyclass(name = "NetworkDecisionStream")]
pub struct PyNetworkDecisionStream {
    stream: Arc<Mutex<DecisionStreamInner>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PyNetworkDecisionStream {
    pub fn new(
        stream: impl futures::Stream<
            Item = microsandbox::MicrosandboxResult<microsandbox::NetworkDecisionItem>,
        > + Send
        + 'static,
    ) -> Self {
        Self {
            stream: Arc::new(Mutex::new(Box::pin(stream))),
        }
    }
}

#[pymethods]
impl PyNetworkDecisionStream {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let stream = self.stream.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut guard = stream.lock().await;
            match guard.next().await {
                Some(Ok(microsandbox::NetworkDecisionItem::Event(event))) => {
                    Ok(convert_event(&event))
                }
                Some(Ok(microsandbox::NetworkDecisionItem::End(_))) => {
                    Err(pyo3::exceptions::PyStopAsyncIteration::new_err(()))
                }
                Some(Err(e)) => Err(to_py_err(e)),
                None => Err(pyo3::exceptions::PyStopAsyncIteration::new_err(())),
            }
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub fn convert_event(event: &microsandbox_network::NetworkDecisionEvent) -> PyNetworkDecision {
    PyNetworkDecision {
        sequence: event.sequence,
        timestamp: event.timestamp.clone(),
        phase: serde_json::to_value(event.phase)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default(),
        action: serde_json::to_value(event.action)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default(),
        reason: event.reason.clone(),
        destination_host: event.destination_host.clone(),
        destination_ip: event.destination_ip.map(|ip| ip.to_string()),
        destination_port: event.destination_port,
        transport: event.transport.clone(),
        protocol: event.protocol.clone(),
        sni: event.sni.clone(),
        http_authority: event.http_authority.clone(),
        correlation_id: event.correlation_id.clone(),
        matched_rule: event.matched_rule.clone(),
        dropped_count: event.dropped_count,
        earliest_retained_sequence: event.earliest_retained_sequence,
    }
}
