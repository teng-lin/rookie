# rookie-cookies (Rust)

Extract cookies from local browsers on Linux, macOS, and Windows.

This file is the **Rust crate guide** (crates.io landing page and repo
tutorial). Python and Node live in
[`bindings/python/README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/bindings/python/README.md)
and
[`bindings/node/README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/bindings/node/README.md).
The monorepo front door is the root
[`README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/README.md).

The workspace is currently `0.6.0-beta.1`. The recommended 0.6 entry is
`read(ReadRequest::…)`
([ADR 0004](https://github.com/teng-lin/rookie-cookies/blob/main/docs/adr/0004-read-is-the-recommended-entry.md)).

```console
cargo add rookie-cookies
```

## Recommended 0.6.0 usage

```rust
use rookie_cookies::{read, ReadRequest, SendContext};

fn main() -> rookie_cookies::Result<()> {
    // Selecting a profile no longer implies session cookies; ask for them with
    // `.include_session()`.
    let snapshot = read(ReadRequest::browser("firefox").profile("default-release"))?;
    for cookie in snapshot.cookies() {
        println!("{} {}", cookie.domain, cookie.name);
    }
    let header = snapshot.header(&SendContext::url("https://example.com/"))?;
    let owned = snapshot.into_cookies();
    let _ = (header, owned);
    Ok(())
}
```

`read` is the recommended job: one unfiltered snapshot, then
`header(&SendContext)` as a view. There is **no** crate-root `get` or `report`
function. Bindings-facing `profiles(browser_id)` exists as an alias of
`browser_profiles`; structured reports use `extract_report` / `browser_report`.

- No-profile `read(ReadRequest::browser("chrome"))` matches the compatibility
  flatten used by `chrome()` / `extract` when `include_expired` is set
  appropriately (persistent / legacy-eligible cookies).
- A profile query selects exactly one profile. For Gecko-family browsers, it
  also includes that profile's separately declared session JSON source.
- Chromium registrations declare no separate session source, so a Chrome
  profile query cannot recover session state that exists only in memory.

Named helpers (`chrome`, `firefox`, `brave`, `load`, …) are `#[deprecated]` since 0.6.0
in favor of `browser` / `extract` / `read` and remain supported through the
deprecation window. They are the compatibility bridge from
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) and will break
in a later major version.

## One operation, any registered browser

`browser(id, domains)` and `extract(ExtractRequest::browser(id))` remain the
compatibility / multi-id store verbs. Prefer them when you need a domain filter
on the frozen flat list; prefer `read` for profile-scoped inventory and Gecko
session import.

```rust
fn main() -> rookie_cookies::Result<()> {
    let request = rookie_cookies::ExtractRequest::browser("chrome")
        .domains(Some(vec!["example.com".to_string()]));
    let cookies = rookie_cookies::extract(request)?;
    println!("{cookies:?}");
    Ok(())
}
```

## Explicit paths

```rust
use std::path::PathBuf;
use rookie_cookies::direct_path::{
    chromium_cookies_from_path_detailed, cookies_from_path, ChromiumCredentialSource,
    ChromiumPathRequest, DirectPathRequest,
};

fn main() -> rookie_cookies::Result<()> {
    let mozilla = cookies_from_path(DirectPathRequest::new(PathBuf::from(
        "/path/to/cookies.sqlite",
    )))?;
    let chromium = chromium_cookies_from_path_detailed(
        ChromiumPathRequest::new("/path/to/Network/Cookies")
            .domains(vec!["example.com".to_owned()])
            .credentials(ChromiumCredentialSource::BrowserId("brave".to_owned())),
    )?;
    println!("{} {}", mozilla.len(), chromium.len());
    Ok(())
}
```

Every 0.6 job function returns `rookie_cookies::Result`, whose error is the
typed `rookie_cookies::Error`:

```rust
match rookie_cookies::direct_path::cookies_from_path(
    rookie_cookies::direct_path::DirectPathRequest::new("/path/to/Cookies"),
) {
    Ok(cookies) => println!("{}", cookies.len()),
    Err(rookie_cookies::Error::Source(source)) => {
        eprintln!("{} {}", source.kind(), source.code());
    }
    Err(error) => eprintln!("{} {error}", error.code()),
}
```

`Error` has four variants — `Request` (caller input), `Stopped` (timeout,
cancellation, resource ceiling), `Source` (an explicit path or path option),
and `Engine` (discovery, acquisition, decryption). `Error::code()` is the
stable machine-readable identifier for all four; never branch on `Display`.

`*_based`, `any_browser`, and the other v0.5.9 bridge functions remain through
0.6 and are deprecated for 0.7. They still return `anyhow::Result`, so the two
error types coexist for the 0.6.x line; `rookie_cookies::anyhow` is re-exported
so their signatures stay nameable.

## Timeouts and cancellation

```rust
use std::time::Duration;

fn main() -> rookie_cookies::Result<()> {
    let cancellation = rookie_cookies::CancellationHandle::new();
    let watcher = cancellation.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(5));
        watcher.cancel();
    });

    let request = rookie_cookies::ExtractRequest::browser("chrome")
        .timeout(Duration::from_secs(30))
        .cancellation(cancellation);
    match rookie_cookies::extract(request) {
        Ok(cookies) => println!("{cookies:?}"),
        Err(error) => match error.stop_reason() {
            Some(rookie_cookies::StopReason::TimedOut) => println!("timed out"),
            Some(rookie_cookies::StopReason::Cancelled) => println!("cancelled"),
            _ => return Err(error),
        },
    }
    Ok(())
}
```

Every request type accepts the same execution knobs, because they are one
composed value rather than five copies:

```rust
use rookie_cookies::{AppBoundPolicy, ExecutionControl, ReadRequest};
use std::time::Duration;

let control = ExecutionControl::default()
    .timeout(Duration::from_secs(10))
    .app_bound(AppBoundPolicy::InjectionOnly);

// `.execution` replaces the control wholesale, so set it first and adjust
// individual fields after.
let request = ReadRequest::browser("chrome").execution(control.clone());
let report = rookie_cookies::load_report_with(
    rookie_cookies::LoadReportRequest::default().execution(control),
);
# let _ = (request, report);
```

The v0.5.9 listing and aggregate signatures (`load_report`,
`browser_profiles`, `chrome_profiles`, `profiles`) are unchanged; the knobs
arrive through `load_report_with`, `browser_profiles_with`,
`chrome_profiles_with`, and `profiles_with`. `supported_browsers` reads the
embedded catalog and does no I/O, so it has no control twin.

Match on `Error` to separate a caller mistake from an engine failure; the free
`fault_kind` / `stop_reason` functions and `Error::fault_kind` are deprecated
in 0.6.0 because a two-way split collapses three of the four variants.

## Snapshots keep isolation

`read` and `from_path` return a `ReadResult` whose native representation is
`DetailedCookie`, so CHIPS partition keys and Firefox container identity
survive the job boundary:

```rust
use rookie_cookies::{read, ReadRequest};

fn main() -> rookie_cookies::Result<()> {
    let snapshot = read(ReadRequest::browser("chrome").profile("Default"))?;
    for detailed in snapshot.detailed_cookies() {
        println!(
            "{} {} partition={:?} container={:?}",
            detailed.cookie.domain,
            detailed.cookie.name,
            detailed.context.top_frame_site_key,
            detailed.context.user_context_id,
        );
    }
    // The eight-field projection is still a free borrow; it discards isolation.
    println!("{} cookies", snapshot.cookies().len());
    Ok(())
}
```

`cookies()` is backed by a projection built once at construction, so the
snapshot holds two copies of every name and value. `into_cookies()` and
`into_detailed_cookies()` move instead of duplicating.

`ReadResult::browser_id()` returns `Option<&str>`; `from_path` returns `None`
because it never passes through browser discovery. A row whose host identity
did not survive decode is **omitted** from the snapshot and counted under the
`malformed_host_identity` warning rather than emitted as `domain: ""`.

## Send-safe headers

`ReadResult::header` takes a `SendContext`, not a bare URL. A URL alone cannot
say which browsing context a request is made from, so the 0.6-beta
`header(url)` had no way to tell a CHIPS-partitioned cookie from an
unpartitioned one — it merged them.

```rust
use rookie_cookies::{read, MethodClass, ReadRequest, SendContext};

fn main() -> rookie_cookies::Result<()> {
    let snapshot = read(ReadRequest::browser("chrome"))?;
    let header = snapshot.header(
        &SendContext::url("https://api.example.com/v1/me")
            .top_level_site("https://app.example.com")
            .navigation()
            .method(MethodClass::Safe),
    )?;
    println!("{header}");
    Ok(())
}
```

A snapshot **demands** a selector as soon as one cookie positively observes the
corresponding isolated value — one partitioned cookie is enough, there is no
identity-count threshold. Omitting it is
`RequestError::IncompleteSendContext`, whose `required` names the missing
selectors as stable identifiers, in this order:

| Selector | Demanded when the snapshot contains |
| --- | --- |
| `top_level_site` | any cookie with a non-empty `top_frame_site_key` **or** `partition_key` |
| `user_context_id` | any cookie with `user_context_id == Some(n)`, `n > 0` |
| `private_browsing_id` | any cookie with `private_browsing_id == Some(n)`, `n > 0` |

`None` and `Some(0)` never demand a selector; gating on them would make
`header` unusable against every browser version whose schema lacks these
columns. Once a selector *is* supplied, cookies in other partitions or
containers are **omitted**, not an error.

**Stated limitations.** `Site` is (scheme, host) — this crate has no
public-suffix list — so `https://cdn.example.com` and `https://app.example.com`
are cross-site here and same-site to a browser. `SameSite=Lax`/`Strict` is
therefore conservative: it omits cookies a browser would send, never the
reverse. CHIPS ancestor state is retained on the snapshot but not gated on, so
a partitioned cookie may be over-included within a matching key. There is one
same-site rule, not a schemeful/legacy dual mode. A caller needing
browser-exact behavior needs a browser.

## Session cookies are their own question

```rust
use rookie_cookies::{read, ReadRequest};

fn main() -> rookie_cookies::Result<()> {
    // 0.6-beta reached session cookies only by naming a profile, and always
    // did. Now the two are separate, and this is expressible:
    let snapshot = read(ReadRequest::browser("firefox").include_session())?;
    println!("{}", snapshot.cookies().len());
    Ok(())
}
```

`SessionPolicy` defaults to `PersistentOnly`, and it is an **acquire-time**
filter: without `include_session()` the crate never opens `sessionstore.js` or
`recovery.jsonlz4`. Report jobs (`extract_report`, `browser_report`,
`load_report`) always retain session sources. Chromium browsers declare no
separate session source, so the policy is a no-op there.

**Migration trap:** `read(...).profile("Default")` on a Gecko browser returned
session cookies in 0.6-beta and does not in 0.6.0 without `include_session()`.
It fails quietly — a smaller list, no error.

## Windows App-Bound (v20)

`AppBoundPolicy` selects, per job, how far the crate may go to recover a
Chrome 127+ App-Bound key:

| Policy | Behavior |
| --- | --- |
| `Disabled` (default) | No injection, no browser process spawn, no process enumeration, no SYSTEM impersonation. v20 rows stay unreadable. |
| `InjectionOnly` | Unprivileged reflective COM injection only. |
| `AllowElevatedFallback` | Injection, then elevated SYSTEM impersonation. |

**The default changed the reachable rows, on purpose.** A Windows caller who
needs v20 cookies must now ask: `ReadRequest::browser("chrome").app_bound(
AppBoundPolicy::InjectionOnly)`. The deprecated v0.5.9 bridge (`chrome`,
`browser`, `chromium_based`, …) keeps `AllowElevatedFallback`, so its 0.5.8
capability is unchanged.

The policy is request-local and immutable once the job starts; it is never
read from the process environment. On non-Windows targets it is a no-op, and
on a build without the `appbound` feature a non-`Disabled` policy is reported
at the v20 lookup — not at the job edge, so a Firefox read or a profile
listing on that build is unaffected.

## Reports and profiles

```rust
fn main() -> rookie_cookies::Result<()> {
    let profiles = rookie_cookies::browser_profiles("chrome")?;
    if let Some(preferred) = profiles.first() {
        let report = rookie_cookies::browser_report(
            "chrome",
            Some(preferred.profile.profile_id.as_str()),
            None,
        )?;
        println!("{}", report.status);
    }
    Ok(())
}
```

`load()` / `load_report()` probe registered browsers concurrently on a bounded
worker pool sharing one deadline / cancellation budget.

## 0.5.6 API

In the 0.5.6 line the public surface was the flat named-browser helpers. There
was no `read` / `ReadRequest` job API, no typed `direct_path` builders, and no
typed `Error` hierarchy. Upstream published the `rookie` crate.

```rust
fn main() {
    let cookies = rookie_cookies::chrome(None).unwrap();
    for cookie in cookies {
        println!("{:?}", cookie);
    }

    let domains = vec!["example.com".to_string()];
    let filtered = rookie_cookies::brave(Some(domains)).unwrap();
    println!("{}", filtered.len());
}
```

## Migrate 0.5.6 → 0.6.0

| Area | 0.5.6 / early 0.5.x | 0.6.0 |
| --- | --- | --- |
| Recommended entry | `chrome(None)` / `brave(Some(domains))` | `read(ReadRequest::browser(...).profile(...))` |
| Multi-id store verb | Named helpers only | Prefer `browser(id, domains)` / `extract(ExtractRequest::…)` |
| Gecko session cookies | Not a first-class `profile()` | `ReadRequest::browser(gecko_id).profile(query)` includes the declared session source |
| Path APIs | `*_based`, `any_browser` | `direct_path::{cookies_from_path, ChromiumPathRequest, …}` (legacy deprecated until 0.7) |
| Errors | Flat `anyhow::Error` | Typed `rookie_cookies::Error` (`Request` / `Stopped` / `Source` / `Engine`) with a stable `code()`. **`rookie_cookies::Result` is no longer `anyhow::Result`**; bridge functions keep `anyhow::Result` and `rookie_cookies::anyhow::Result` still resolves |
| Header / get | Not a job view | `ReadResult::header(url)` — **no** crate-root `get` or `report` |
| IE helpers | `internet_explorer` / `internet_explorer_based` | Deprecated (ESE native C library; IE discontinued) |

1. For Gecko session import, select the exact profile, for example
   `read(ReadRequest::browser("firefox").profile("default-release"))`.
2. Prefer `browser` / `extract` for flat domain-filtered lists.
3. Move explicit DB paths onto `direct_path` builders.
4. Classify failures by matching `rookie_cookies::Error` (or comparing `error.code()`).
5. Do not add crate-root `get` / `report`.

See [CHANGELOG.md](https://github.com/teng-lin/rookie-cookies/blob/main/CHANGELOG.md).

## Logging

```console
RUST_LOG=trace cargo run
```

## More

- [docs/building.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/building.md)
- [docs/testing.md](https://github.com/teng-lin/rookie-cookies/blob/main/docs/testing.md)
- [teng-lin/rookie-cookies](https://github.com/teng-lin/rookie-cookies)
