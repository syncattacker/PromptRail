//! PromptRail WS1 capture-verification harness.
//!
//! This is a *runtime* binary (not an xtask): it runs as a process alongside the
//! daemon, generates real HTTPS traffic through OpenSSL-linked `curl`, and gives
//! the operator a deterministic way to confirm capture.
//!
//! ## How verification works (manual assertion, by design for WS1)
//!
//! End-to-end automated assertion would require the harness to read the same
//! ring buffer the daemon owns — two readers of one map is the wrong shape.
//! Instead:
//!   1. Start the daemon in one terminal.
//!   2. Run this harness in another. Each request carries a unique **canary**
//!      header, so its bytes appear verbatim in the `SSL_write` plaintext.
//!   3. Confirm the daemon printed a `plaintext:` line containing the canary,
//!      attributed to `comm=curl`. Grepping the daemon's stdout for the canary
//!      is the assertion.
//!
//! Soak mode (`--duration`/`--rate`) drives sustained traffic so you can watch
//! the daemon's `capture stats (clean)` line stay drop-free for the exit gate.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use promptrail_common::{Event, MAX_PAYLOAD};

/// Parsed command-line configuration.
struct Config {
    url: String,
    canary: String,
    duration: Duration,
    rate: f64,
}

impl Config {
    fn from_args() -> Result<Self> {
        // Minimal hand-rolled parser to avoid a clap dependency in a test tool.
        let mut url = "https://example.com/".to_owned();
        let mut canary = default_canary();
        let mut duration = Duration::from_secs(60);
        let mut rate = 5.0_f64;

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--url" => url = next_value(&mut args, "--url")?,
                "--canary" => canary = next_value(&mut args, "--canary")?,
                "--duration" => {
                    duration = Duration::from_secs(
                        next_value(&mut args, "--duration")?
                            .parse()
                            .context("--duration must be an integer number of seconds")?,
                    )
                }
                "--rate" => {
                    rate = next_value(&mut args, "--rate")?
                        .parse()
                        .context("--rate must be a number (requests per second)")?
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => bail!("unknown argument: {other} (try --help)"),
            }
        }

        if rate <= 0.0 {
            bail!("--rate must be positive");
        }
        Ok(Self {
            url,
            canary,
            duration,
            rate,
        })
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String> {
    args.next().with_context(|| format!("{flag} requires a value"))
}

/// A canary unique enough for a single run: unix-nanos plus this pid.
fn default_canary() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("promptrail-canary-{}-{}", std::process::id(), nanos)
}

fn print_usage() {
    eprintln!(
        "promptrail-test-harness — HTTPS load generator for WS1 capture verification\n\n\
         USAGE:\n  promptrail-test-harness [--url URL] [--canary STR] [--duration SECS] [--rate RPS]\n\n\
         Defaults: --url https://example.com/  --duration 60  --rate 5\n\n\
         Run the daemon first, then run this and grep the daemon output for the canary."
    );
}

fn main() -> Result<()> {
    // ABI guard: because we link promptrail-common, a size mismatch here means
    // the harness and daemon were built against different ABI versions. Print it
    // so a confusing "no capture" is easy to diagnose.
    println!(
        "ABI: Event = {} bytes, MAX_PAYLOAD = {} bytes",
        core::mem::size_of::<Event>(),
        MAX_PAYLOAD
    );

    ensure_curl_present()?;
    let cfg = Config::from_args()?;

    println!("canary: {}", cfg.canary);
    println!(
        "driving {} for {}s at ~{} req/s — watch the daemon for a plaintext line containing the canary",
        cfg.url,
        cfg.duration.as_secs(),
        cfg.rate
    );

    run_soak(&cfg)
}

/// Verify `curl` exists and is linked against a TLS library, so requests exercise
/// `SSL_write`/`SSL_read`. A curl built without TLS would silently never trigger
/// the probes.
fn ensure_curl_present() -> Result<()> {
    let out = Command::new("curl")
        .arg("--version")
        .output()
        .context("could not execute `curl` — is it installed and on PATH?")?;
    if !out.status.success() {
        bail!("`curl --version` failed");
    }
    let banner = String::from_utf8_lossy(&out.stdout);
    // The first line lists TLS backends, e.g. "... OpenSSL/3.x ...".
    if !(banner.contains("OpenSSL") || banner.contains("SSL")) {
        eprintln!(
            "warning: curl does not appear to be OpenSSL-linked; the OpenSSL uprobe may not fire.\n{}",
            banner.lines().next().unwrap_or("")
        );
    }
    Ok(())
}

/// Issue requests at the configured rate for the configured duration.
fn run_soak(cfg: &Config) -> Result<()> {
    let interval = Duration::from_secs_f64(1.0 / cfg.rate);
    let start = Instant::now();
    let mut sent = 0_u64;
    let mut failed = 0_u64;

    while start.elapsed() < cfg.duration {
        let next_deadline = Instant::now() + interval;
        match fire_request(cfg) {
            Ok(true) => sent += 1,
            Ok(false) => {
                sent += 1;
                failed += 1;
            }
            Err(e) => {
                // A spawn failure (not an HTTP failure) is worth stopping for.
                bail!("failed to launch curl: {e}");
            }
        }

        // Pace to the target rate; if a request took longer than the interval,
        // fire the next immediately rather than trying to "catch up" in a burst.
        let now = Instant::now();
        if now < next_deadline {
            std::thread::sleep(next_deadline - now);
        }
    }

    println!(
        "soak complete: {sent} requests issued ({failed} returned non-success). \
         Confirm the daemon logged the canary and reported no drops."
    );
    Ok(())
}

/// Fire a single HTTPS request carrying the canary header. Returns Ok(true) on
/// HTTP success, Ok(false) on a non-success HTTP result, Err only if curl could
/// not be spawned.
fn fire_request(cfg: &Config) -> Result<bool> {
    // The canary rides in a request header, so it is part of the plaintext the
    // client hands to SSL_write — exactly what the daemon should capture.
    let status = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            "10",
            "--output",
            "/dev/null",
            "-H",
        ])
        .arg(format!("X-PromptRail-Canary: {}", cfg.canary))
        .arg(&cfg.url)
        .stdin(Stdio::null())
        .status()
        .context("spawning curl")?;
    Ok(status.success())
}
