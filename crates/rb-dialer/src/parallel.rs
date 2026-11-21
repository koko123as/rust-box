//! Dialing several addresses: one after another (sing `N.DialSerial`) or
//! racing the two address families with a fallback delay (RFC 6555 "happy
//! eyeballs", sing `N.DialParallel` and sing-box
//! `dialer.DialParallelNetwork`).

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::time::Duration;

/// sing `N.DefaultFallbackDelay`.
pub const DEFAULT_FALLBACK_DELAY: Duration = Duration::from_millis(300);

/// Joins the errors of several attempts like sing `E.Errors`.
fn join_errors(errors: Vec<io::Error>) -> io::Error {
    match errors.len() {
        0 => io::Error::new(io::ErrorKind::NotFound, "no addresses to dial"),
        1 => errors.into_iter().next().unwrap(),
        _ => {
            let kind = errors[0].kind();
            let message = errors.iter().map(ToString::to_string).collect::<Vec<_>>().join(" | ");
            io::Error::new(kind, message)
        }
    }
}

/// Tries `addresses` in order and returns the first connection that
/// succeeds.
pub async fn dial_serial<T, F, Fut>(addresses: &[IpAddr], connect: &F) -> io::Result<T>
where
    F: Fn(IpAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut errors = Vec::new();
    for address in addresses {
        match connect(*address).await {
            Ok(conn) => return Ok(conn),
            Err(error) => errors.push(error),
        }
    }
    Err(join_errors(errors))
}

fn is_ipv4(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(_) => true,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
    }
}

/// Races the address families: the preferred family's addresses are tried
/// one after another at once, the other family's start after
/// `fallback_delay` (300ms when zero) or as soon as the preferred ones have
/// all failed, and the first connection wins. With a single family this
/// is [`dial_serial`]. When both fail, the preferred family's error is
/// returned, as sing does.
pub async fn dial_parallel<T, F, Fut>(
    addresses: &[IpAddr],
    prefer_ipv6: bool,
    fallback_delay: Duration,
    connect: &F,
) -> io::Result<T>
where
    F: Fn(IpAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let fallback_delay = if fallback_delay.is_zero() { DEFAULT_FALLBACK_DELAY } else { fallback_delay };
    let (ipv4, ipv6): (Vec<IpAddr>, Vec<IpAddr>) = addresses.iter().partition(|address| is_ipv4(address));
    if ipv4.is_empty() || ipv6.is_empty() {
        return dial_serial(addresses, connect).await;
    }
    let (primaries, fallbacks) = if prefer_ipv6 { (ipv6, ipv4) } else { (ipv4, ipv6) };
    let primary = dial_serial(&primaries, connect);
    tokio::pin!(primary);
    let fallback = dial_serial(&fallbacks, connect);
    tokio::pin!(fallback);
    let timer = tokio::time::sleep(fallback_delay);
    tokio::pin!(timer);
    let mut fallback_started = false;
    let mut primary_error: Option<io::Error> = None;
    let mut fallback_error: Option<io::Error> = None;
    loop {
        tokio::select! {
            result = &mut primary, if primary_error.is_none() => match result {
                Ok(conn) => return Ok(conn),
                Err(error) => {
                    primary_error = Some(error);
                    // The preferred family failed: fall back right away.
                    fallback_started = true;
                }
            },
            _ = &mut timer, if !fallback_started => fallback_started = true,
            result = &mut fallback, if fallback_started && fallback_error.is_none() => match result {
                Ok(conn) => return Ok(conn),
                Err(error) => fallback_error = Some(error),
            },
        }
        if let (Some(_), Some(_)) = (&primary_error, &fallback_error) {
            return Err(primary_error.take().unwrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::time::Instant;

    type Log = Arc<Mutex<Vec<(IpAddr, Duration)>>>;

    /// A connector where each address answers after a delay, with success
    /// or failure, and records when each attempt started.
    fn connector(
        plan: Vec<(&'static str, u64, bool)>,
        log: Log,
        start: Instant,
    ) -> impl Fn(IpAddr) -> std::pin::Pin<Box<dyn Future<Output = io::Result<IpAddr>> + Send>> {
        move |address: IpAddr| {
            let (_, delay, ok) =
                *plan.iter().find(|(text, _, _)| text.parse::<IpAddr>().unwrap() == address).expect("planned address");
            log.lock().unwrap().push((address, start.elapsed()));
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                if ok {
                    Ok(address)
                } else {
                    Err(io::Error::new(io::ErrorKind::ConnectionRefused, format!("{address}: refused")))
                }
            })
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn fallback_after_delay() {
        // IPv6 preferred and hanging: IPv4 starts after the delay and wins.
        let log: Log = Default::default();
        let start = Instant::now();
        let connect = connector(vec![("2001:db8::1", 10_000, true), ("192.0.2.1", 50, true)], log.clone(), start);
        let addresses = [ip("2001:db8::1"), ip("192.0.2.1")];
        let winner = dial_parallel(&addresses, true, Duration::from_millis(250), &connect).await.unwrap();
        assert_eq!(winner, ip("192.0.2.1"));
        let log = log.lock().unwrap();
        assert_eq!(log[0], (ip("2001:db8::1"), Duration::ZERO));
        assert_eq!(log[1], (ip("192.0.2.1"), Duration::from_millis(250)));
        assert_eq!(start.elapsed(), Duration::from_millis(300));
    }

    #[tokio::test(start_paused = true)]
    async fn default_delay_and_preference() {
        let log: Log = Default::default();
        let start = Instant::now();
        let connect = connector(vec![("2001:db8::1", 50, true), ("192.0.2.1", 10_000, true)], log.clone(), start);
        // IPv4 preferred (first address is IPv4) and hanging.
        let winner =
            dial_parallel(&[ip("192.0.2.1"), ip("2001:db8::1")], false, Duration::ZERO, &connect).await.unwrap();
        assert_eq!(winner, ip("2001:db8::1"));
        assert_eq!(log.lock().unwrap()[1].1, DEFAULT_FALLBACK_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn immediate_fallback_on_failure() {
        let log: Log = Default::default();
        let start = Instant::now();
        let connect = connector(vec![("192.0.2.1", 10, false), ("2001:db8::1", 10, true)], log.clone(), start);
        let winner = dial_parallel(&[ip("192.0.2.1"), ip("2001:db8::1")], false, Duration::from_secs(5), &connect)
            .await
            .unwrap();
        assert_eq!(winner, ip("2001:db8::1"));
        assert_eq!(log.lock().unwrap()[1].1, Duration::from_millis(10));
    }

    #[tokio::test(start_paused = true)]
    async fn primary_wins_before_delay() {
        let log: Log = Default::default();
        let start = Instant::now();
        let connect = connector(vec![("192.0.2.1", 20, true), ("2001:db8::1", 1, true)], log.clone(), start);
        let winner =
            dial_parallel(&[ip("192.0.2.1"), ip("2001:db8::1")], false, Duration::ZERO, &connect).await.unwrap();
        assert_eq!(winner, ip("192.0.2.1"));
        assert_eq!(log.lock().unwrap().len(), 1, "the fallback never started");
    }

    #[tokio::test(start_paused = true)]
    async fn both_fail_and_serial() {
        let log: Log = Default::default();
        let start = Instant::now();
        let connect = connector(
            vec![("192.0.2.1", 5, false), ("192.0.2.2", 5, false), ("2001:db8::1", 5, false)],
            log.clone(),
            start,
        );
        let error =
            dial_parallel(&[ip("192.0.2.1"), ip("192.0.2.2"), ip("2001:db8::1")], false, Duration::ZERO, &connect)
                .await
                .unwrap_err();
        // The preferred family's errors, joined.
        assert_eq!(error.to_string(), "192.0.2.1: refused | 192.0.2.2: refused");
        // One family only: serial, in order.
        let log2: Log = Default::default();
        let connect = connector(vec![("192.0.2.1", 5, false), ("192.0.2.2", 5, true)], log2.clone(), start);
        let winner = dial_parallel(&[ip("192.0.2.1"), ip("192.0.2.2")], false, Duration::ZERO, &connect).await.unwrap();
        assert_eq!(winner, ip("192.0.2.2"));
        assert_eq!(log2.lock().unwrap().len(), 2);
    }
}
