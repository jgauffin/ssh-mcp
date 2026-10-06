# Unfiled decisions

### Sending a local file to a host is gated twice

- decided: The approval page is the control for sending a local file to a host — it names the local path, the destination and the content hash, so the user sees what is leaving their disk — but credential-shaped local paths are refused before any page is drawn, and only an explicit allowlist in the config file lifts that refusal.
- affects: sending a local file to a host, approval pages, configuration

### A file sent to a host may not be executable

- decided: Sending a local file to a host refuses an executable: no execute bit may be requested in its mode, and content that begins with an executable's magic bytes is refused whatever mode is asked for. Either gate alone leaks, because a non-executable file still runs under an interpreter and arbitrary content still runs after a later chmod.
- affects: sending a local file to a host

### A file sent to a host is capped at the size the server can also read back

- decided: Sending a local file to a host is capped at the same size as reading a remote file, rather than a larger cap justified by streaming. A file beyond that is a job for the user's own scp.
- affects: sending a local file to a host, reading a remote file
