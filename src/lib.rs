pub mod notify;
pub mod peer;

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use ssh_agent_lib::{
    agent::{self, Agent, ListeningSocket, Session},
    client::Client,
    error::AgentError,
    proto::{extension::QueryResponse, Extension, Identity, SignRequest},
    ssh_key::{public::KeyData as PubKeyData, Signature},
};
use tokio::{
    net::UnixListener,
    net::UnixStream,
    sync::{Mutex, OwnedMutexGuard},
    task::JoinSet,
    time::timeout,
};

const SIGN_TIMEOUT: Duration = Duration::from_secs(60);
const SESSION_BIND_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

type KnownPubKeysMap = HashMap<PubKeyData, PathBuf>;
type KnownPubKeys = Arc<Mutex<KnownPubKeysMap>>;

/// Per-client session with persistent upstream connections.
///
/// Each SSH client connection to the mux gets its own `MuxSession` with
/// its own set of upstream agent connections. This preserves session-bind
/// state across operations: when OpenSSH sends session-bind followed by
/// sign, both go through the same upstream connection, so the host key
/// binding is retained for the signature.
pub struct MuxSession {
    socket_paths: Vec<PathBuf>,
    known_keys: KnownPubKeys,
    upstream: HashMap<PathBuf, Box<dyn Session>>,
    peer: Option<peer::PeerInfo>,
}

impl MuxSession {
    fn peer_display(&self) -> String {
        match &self.peer {
            Some(p) => p.to_string(),
            None => "<unknown>".to_string(),
        }
    }
}

#[ssh_agent_lib::async_trait]
impl Session for MuxSession {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        log::info!("request_identities peer={}", self.peer_display());
        let mut known_keys = self.known_keys.clone().lock_owned().await;
        self.refresh_identities(&mut known_keys).await
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let fingerprint = request.pubkey.fingerprint(Default::default());
        let hash = notify::hash(&request.data);
        let id = &hash[..hash.len().min(7)];
        log::trace!("incoming: sign({}) id={} hash={}", &fingerprint, id, hash);

        let agent_sock_path = match self.get_agent_sock_for_pubkey(&request.pubkey).await? {
            Some(p) => p,
            None => {
                log::error!("No upstream agent found for public key {}", &fingerprint);
                log::trace!("Known keys:\n{:#?}", self.known_keys);
                return Err(AgentError::Other(
                    format!("No agent found for public key: {}", &fingerprint).into(),
                ));
            }
        };

        log::info!(
            "sign id={} hash={} key={} upstream=<{}> peer={}",
            id,
            hash,
            &fingerprint,
            agent_sock_path.display(),
            self.peer_display()
        );

        // Held until function return; Drop closes the notification via D-Bus.
        let _notif = notify::send(
            &format!("ssh-agent-mux: sign [id {}]", id),
            &format!("key {}\npeer {}", fingerprint, self.peer_display()),
        );

        self.ensure_connected(&agent_sock_path).await?;
        let client = self.upstream.get_mut(&agent_sock_path).unwrap();
        let result = timeout(SIGN_TIMEOUT, client.sign(request)).await;

        match result {
            Ok(Ok(sig)) => Ok(sig),
            Ok(Err(e)) => {
                self.upstream.remove(&agent_sock_path);
                Err(e)
            }
            Err(_) => {
                log::error!(
                    "Timeout waiting for signature from upstream agent <{}>",
                    agent_sock_path.display()
                );
                self.upstream.remove(&agent_sock_path);
                Err(AgentError::Failure)
            }
        }
    }

    async fn extension(&mut self, request: Extension) -> Result<Option<Extension>, AgentError> {
        log::trace!("incoming: extension({})", request.name);
        match request.name.as_str() {
            "query" => Ok(Some(Extension::new_message(QueryResponse {
                extensions: ["session-bind@openssh.com"].map(String::from).to_vec(),
            })?)),
            "session-bind@openssh.com" => {
                log::info!("session-bind peer={}", self.peer_display());

                // Forward session-bind to all upstream agents in parallel.
                let mut tasks: JoinSet<(
                    PathBuf,
                    Box<dyn Session>,
                    Result<Option<Extension>, AgentError>,
                )> = JoinSet::new();

                for sock_path in self.socket_paths.clone() {
                    let mut client = match self.upstream.remove(&sock_path) {
                        Some(c) => c,
                        None => match Self::connect(&sock_path).await {
                            Ok(c) => c,
                            Err(_) => continue,
                        },
                    };
                    let req = request.clone();
                    tasks.spawn(async move {
                        let result =
                            match timeout(SESSION_BIND_TIMEOUT, client.extension(req)).await {
                                Ok(r) => r,
                                Err(_) => Err(AgentError::Other("timeout".into())),
                            };
                        (sock_path, client, result)
                    });
                }

                let mut any_succeeded = false;
                while let Some(join_result) = tasks.join_next().await {
                    let (sock_path, client, result) = match join_result {
                        Ok(v) => v,
                        Err(e) => {
                            log::error!("Session-bind task panicked: {}", e);
                            continue;
                        }
                    };
                    match result {
                        Ok(v) => {
                            any_succeeded = true;
                            self.upstream.insert(sock_path.clone(), client);
                            if v.is_some() {
                                log::warn!(
                                    "session-bind succeeded on <{}> but returned unexpected data",
                                    sock_path.display()
                                );
                            }
                        }
                        Err(AgentError::Failure) => {
                            log::debug!(
                                "Upstream <{}> does not support session-bind",
                                sock_path.display()
                            );
                            self.upstream.insert(sock_path, client);
                        }
                        Err(e) => {
                            log::warn!(
                                "Error forwarding session-bind to <{}>: {}",
                                sock_path.display(),
                                e
                            );
                            // Don't re-insert broken connection
                        }
                    }
                }

                if any_succeeded {
                    Ok(None)
                } else {
                    Err(AgentError::Failure)
                }
            }
            _ => Err(AgentError::Failure),
        }
    }
}

impl MuxSession {
    /// Connect to an upstream agent socket.
    async fn connect(sock_path: &Path) -> Result<Box<dyn Session>, AgentError> {
        let stream = match timeout(CONNECT_TIMEOUT, UnixStream::connect(sock_path)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(AgentError::IO(e)),
            Err(_) => {
                return Err(AgentError::Other(
                    format!("Timeout connecting to agent at {}", sock_path.display()).into(),
                ))
            }
        };
        log::trace!(
            "Connected to upstream agent on socket: {}",
            sock_path.display()
        );
        Ok(Box::new(Client::new(stream)))
    }

    /// Ensure a persistent connection exists for the given upstream socket.
    async fn ensure_connected(&mut self, sock_path: &Path) -> Result<(), AgentError> {
        let path_buf = sock_path.to_path_buf();
        if !self.upstream.contains_key(&path_buf) {
            let client = Self::connect(sock_path).await?;
            self.upstream.insert(path_buf, client);
        }
        Ok(())
    }

    async fn get_agent_sock_for_pubkey(
        &mut self,
        pubkey: &PubKeyData,
    ) -> Result<Option<PathBuf>, AgentError> {
        let mut known_keys = self.known_keys.clone().lock_owned().await;
        if !known_keys.contains_key(pubkey) {
            log::debug!("Key not found, re-requesting keys from upstream agents");
            let _ = self.refresh_identities(&mut known_keys).await?;
        }
        let maybe_agent = known_keys.get(pubkey).cloned();
        Ok(maybe_agent)
    }

    async fn refresh_identities(
        &mut self,
        known_keys: &mut OwnedMutexGuard<KnownPubKeysMap>,
    ) -> Result<Vec<Identity>, AgentError> {
        let mut identities = vec![];
        known_keys.clear();

        log::debug!("Refreshing identities");

        // Take existing connections out and connect to any missing agents.
        // Each agent is then queried for identities in parallel.
        let mut tasks: JoinSet<(PathBuf, Box<dyn Session>, Result<Vec<Identity>, AgentError>)> =
            JoinSet::new();

        for sock_path in self.socket_paths.clone() {
            let mut client = match self.upstream.remove(&sock_path) {
                Some(c) => c,
                None => match Self::connect(&sock_path).await {
                    Ok(c) => c,
                    Err(_) => {
                        log::warn!(
                            "Ignoring missing upstream agent socket: {}",
                            sock_path.display()
                        );
                        continue;
                    }
                },
            };
            tasks.spawn(async move {
                let result = match timeout(UPSTREAM_TIMEOUT, client.request_identities()).await {
                    Ok(r) => r,
                    Err(_) => Err(AgentError::Other("timeout".into())),
                };
                (sock_path, client, result)
            });
        }

        while let Some(join_result) = tasks.join_next().await {
            let (sock_path, client, result) = match join_result {
                Ok(v) => v,
                Err(e) => {
                    log::error!("Identity task panicked: {}", e);
                    continue;
                }
            };
            match result {
                Ok(ids) => {
                    log::trace!(
                        "Got {} identities from {}",
                        ids.len(),
                        sock_path.display()
                    );
                    for id in &ids {
                        known_keys.insert(id.pubkey.clone(), sock_path.clone());
                    }
                    identities.extend(ids);
                    self.upstream.insert(sock_path, client);
                }
                Err(e) => {
                    log::warn!(
                        "Failed to list identities from upstream agent <{}>: {}",
                        sock_path.display(),
                        e
                    );
                }
            }
        }

        Ok(identities)
    }
}

/// Shared agent state. Cloned for each listener accept; creates a fresh
/// `MuxSession` (with empty connection cache) per client.
#[derive(Clone)]
pub struct MuxAgent {
    socket_paths: Vec<PathBuf>,
    known_keys: KnownPubKeys,
}

impl MuxAgent {
    /// Run a MuxAgent, listening for SSH agent protocol requests on `listen_sock`, forwarding
    /// requests to the specified paths in `agent_socks`
    pub async fn run<I, P>(listen_sock: impl AsRef<Path>, agent_socks: I) -> Result<(), AgentError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let listen_sock = listen_sock.as_ref();
        let socket_paths: Vec<_> = agent_socks
            .into_iter()
            .map(|p| p.as_ref().to_path_buf())
            .collect();
        if socket_paths.is_empty() {
            log::warn!("Mux agent running but no upstream agents configured");
        }
        log::info!(
            "Starting agent for {} upstream agents; listening on <{}>",
            socket_paths.len(),
            listen_sock.display()
        );
        log::debug!("Upstream agent sockets: {:?}", &socket_paths);

        let listen_sock = match SelfDeletingUnixListener::bind(listen_sock) {
            Ok(s) => s,
            err => {
                log::error!(
                    "Failed to open listening socket at {}",
                    listen_sock.display()
                );
                err?
            }
        };
        let this = Self {
            socket_paths,
            known_keys: Default::default(),
        };
        agent::listen(listen_sock, this).await
    }
}

impl Agent<SelfDeletingUnixListener> for MuxAgent {
    #[doc = "Create new session object when a new socket is accepted."]
    fn new_session(
        &mut self,
        socket: &<SelfDeletingUnixListener as ListeningSocket>::Stream,
    ) -> impl Session {
        let peer = peer::PeerInfo::capture(socket);
        match &peer {
            Some(p) => log::info!("new session: {}", p),
            None => log::info!("new session: <peer unknown>"),
        }
        MuxSession {
            socket_paths: self.socket_paths.clone(),
            known_keys: self.known_keys.clone(),
            upstream: HashMap::new(),
            peer,
        }
    }
}

#[derive(Debug)]
/// A wrapper for UnixListener that keeps the socket path around so it can be deleted
struct SelfDeletingUnixListener {
    path: PathBuf,
    listener: UnixListener,
}

impl SelfDeletingUnixListener {
    fn bind(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        UnixListener::bind(&path).map(|listener| Self { path, listener })
    }
}

impl Drop for SelfDeletingUnixListener {
    fn drop(&mut self) {
        log::debug!("Cleaning up socket {}", self.path.display());
        let _ = std::fs::remove_file(&self.path);
    }
}

#[ssh_agent_lib::async_trait]
impl ListeningSocket for SelfDeletingUnixListener {
    type Stream = tokio::net::UnixStream;

    async fn accept(&mut self) -> std::io::Result<Self::Stream> {
        UnixListener::accept(&self.listener)
            .await
            .map(|(s, _addr)| s)
    }
}
