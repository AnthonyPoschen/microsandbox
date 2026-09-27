//! Network-policy decision replay and follow APIs.

use std::pin::Pin;

use futures::Stream;
use futures::StreamExt;
use futures::stream;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::Sandbox;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for [`Sandbox::network_decisions`] and
/// [`Sandbox::network_decision_stream`].
#[derive(Clone, Copy, Debug, Default)]
pub struct NetworkDecisionOptions {
    /// Exclusive sequence cursor. `0` starts at the oldest retained event.
    pub after_sequence: u64,
    /// When true, keep the stream open until the sandbox stops or the
    /// caller drops it.
    pub follow: bool,
}

/// Terminal state of a decision stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkDecisionEnd {
    /// Snapshot drained and follow was false.
    Drained,
    /// The sandbox stopped or the decision log closed.
    SandboxStopped,
}

/// One item from a decision stream.
#[derive(Clone, Debug)]
pub enum NetworkDecisionItem {
    /// An enforcement event.
    Event(microsandbox_network::NetworkDecisionEvent),
    /// Explicit end-of-stream.
    End(NetworkDecisionEnd),
}

/// Boxed stream of network decisions.
pub type NetworkDecisionStream =
    Pin<Box<dyn Stream<Item = MicrosandboxResult<NetworkDecisionItem>> + Send + 'static>>;

#[derive(Deserialize)]
struct DoneLine {
    #[serde(default)]
    done: bool,
    #[serde(default)]
    reason: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Read buffered network-policy decisions after `opts.after_sequence`.
    ///
    /// Local backend only. The ring buffer lives in the sandbox process;
    /// a stopped sandbox cannot replay events.
    pub async fn network_decisions(
        &self,
        opts: NetworkDecisionOptions,
    ) -> MicrosandboxResult<microsandbox_runtime::control::NetworkDecisionSnapshot> {
        local_network_decisions(self.name(), opts).await
    }

    /// Replay buffered decisions, then optionally follow new ones.
    ///
    /// The stream yields [`NetworkDecisionItem::Event`] values and then an
    /// explicit [`NetworkDecisionItem::End`]. Local backend only.
    pub fn network_decision_stream(&self, opts: NetworkDecisionOptions) -> NetworkDecisionStream {
        local_network_decision_stream(self.name().to_string(), opts)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn local_network_decisions(
    name: &str,
    opts: NetworkDecisionOptions,
) -> MicrosandboxResult<microsandbox_runtime::control::NetworkDecisionSnapshot> {
    let request = serde_json::json!({
        "op": "network_decisions",
        "after": opts.after_sequence,
    });
    let mut line = serde_json::to_string(&request)?;
    line.push('\n');
    let response = super::modify::control_request(name, line).await?;
    response.network_decisions.ok_or_else(|| {
        MicrosandboxError::Runtime("control response missing network decisions".into())
    })
}

pub(crate) fn local_network_decision_stream(
    name: String,
    opts: NetworkDecisionOptions,
) -> NetworkDecisionStream {
    Box::pin(
        stream::once(async move { connect_and_read(name, opts).await })
            .then(|result| async move {
                match result {
                    Ok(stream) => stream,
                    Err(error) => {
                        Box::pin(stream::once(async move { Err(error) })) as NetworkDecisionStream
                    }
                }
            })
            .flatten(),
    )
}

async fn connect_and_read(
    name: String,
    opts: NetworkDecisionOptions,
) -> MicrosandboxResult<NetworkDecisionStream> {
    #[cfg(unix)]
    {
        let request = serde_json::json!({
            "op": "network_decision_stream",
            "after": opts.after_sequence,
            "follow": opts.follow,
        });
        let mut line = serde_json::to_string(&request)?;
        line.push('\n');
        let mut stream = super::modify::connect_control_socket(
            super::modify::control_socket_path_candidates(&name),
        )
        .await
        .map_err(|error| {
            MicrosandboxError::Runtime(format!(
                "failed to reach a runtime control socket for sandbox {name:?}: {error}"
            ))
        })?;
        stream.write_all(line.as_bytes()).await.map_err(|e| {
            MicrosandboxError::Runtime(format!("network decision stream request failed: {e}"))
        })?;
        let reader = BufReader::new(stream);
        Ok(Box::pin(stream::unfold(
            Some(reader),
            |reader| async move {
                let mut reader = reader?;
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(0) => Some((
                        Ok(NetworkDecisionItem::End(NetworkDecisionEnd::SandboxStopped)),
                        None,
                    )),
                    Ok(_) => {
                        if let Some(end) = parse_done_line(&line) {
                            Some((Ok(NetworkDecisionItem::End(end)), None))
                        } else {
                            match serde_json::from_str::<microsandbox_network::NetworkDecisionEvent>(
                                line.trim(),
                            ) {
                                Ok(event) => {
                                    Some((Ok(NetworkDecisionItem::Event(event)), Some(reader)))
                                }
                                Err(error) => Some((Err(error.into()), None)),
                            }
                        }
                    }
                    Err(error) => Some((
                        Err(MicrosandboxError::Runtime(format!(
                            "network decision stream read failed: {error}"
                        ))),
                        None,
                    )),
                }
            },
        )))
    }
    #[cfg(not(unix))]
    {
        let _ = (name, opts);
        Err(MicrosandboxError::Runtime(
            "network decision follow requires a unix control socket".into(),
        ))
    }
}

fn parse_done_line(line: &str) -> Option<NetworkDecisionEnd> {
    let parsed: DoneLine = serde_json::from_str(line.trim()).ok()?;
    if !parsed.done {
        return None;
    }
    Some(match parsed.reason.as_deref() {
        Some("sandbox_stopped") => NetworkDecisionEnd::SandboxStopped,
        _ => NetworkDecisionEnd::Drained,
    })
}
