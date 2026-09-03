# rookie-cookies (Rust)

Extract cookies from local browsers on Linux, macOS, and Windows.

This file is the **Rust crate guide** (crates.io landing page and repo
tutorial). Python and Node live in
[`bindings/python/README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/bindings/python/README.md)
and
[`bindings/node/README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/bindings/node/README.md).
The monorepo front door is the root
[`README.md`](https://github.com/teng-lin/rookie-cookies/blob/main/README.md).

The recommended entry is `read(ReadRequest::…)`, then
`send_view(&SendContext)` for anything you intend to send
([ADR 0004](https://github.com/teng-lin/rookie-cookies/blob/main/docs/adr/0004-read-is-the-recommended-entry.md),
[ADR 0006](https://github.com/teng-lin/rookie-cookies/blob/main/docs/adr/0006-isolation-safe-send-selection-and-explicit-isolation-loss.md)).
Crate metadata and `version()` identify the installed build.
The minimum supported Rust version (MSRV) is 1.88.

```console
cargo add rookie-cookies
```

> **Windows App-Bound security note:** jobs default to
> `AppBoundPolicy::InjectionOnly`, which reflectively injects into a spawned
> browser process and may be flagged by endpoint security. Chain
> `.app_bound(AppBoundPolicy::Disabled)` to perform no App-Bound process work;
> `v20` rows will then be omitted with a warning.

## Recommended usage (0.7 series)

```rust
use rookie_cookies::{read, ReadRequest, SendContext};

fn main() -> rookie_cookies::Result<()> {
    // Selecting a profile no longer implies session cookies; ask for them with
    // `.include_session()`.
    let snapshot = read(
        ReadRequest::browser("firefox")
            .profile("default-release")
            .include_session(),
    )?;
    for cookie in snapshot.cookies() {
        println!("{} {}", cookie.domain, cookie.name);
    }
    // The send-side view: which records this browsing context selects, the
    // header they render to, and what was left out.
    let view = snapshot.send_view(
        &SendContext::url("https://app.example.com/")
            .top_level_site("https://example.com"),
    )?;
    println!("{} {}", view.header(), view.omitted().partition());
    Ok(())
}
```

`read` is the recommended job: one unfiltered snapshot, then
`send_view(&SendContext)` as a view over it. There is **no** crate-root `get`
or `report` function. Bindings-facing `profiles(browser_id)` exists as an
alias of `browser_profiles`; structured reports use `extract_report` /
`browser_report`.

`jar(request)` is `read(request)?.into_jar()` — the *compatibility*
projection, not the send path. It returns Rust's language-native
`Vec<Cookie>`, discards warnings, and fails closed rather than discarding
partition/container context: an isolated snapshot returns
`RequestError::IsolationLossRefused` (code `isolation_loss_refused`) until
the caller names the loss with `jar_with`/`into_jar_with` and
`IsolationLoss::Allow`. `cookies()` / `into_cookies()` stay infallible — they
are the inventory projection, for looking at rows rather than sending them.

- No-profile `read(ReadRequest::browser("chrome"))` matches the compatibility
  flatten used by `chrome()` / `extract` when `include_expired` is set
  appropriately (persistent / legacy-eligible cookies).
- A profile query selects exactly one profile. Session inclusion is a separate
  policy: `.include_session()` acquires the selected Gecko profile's declared
  session JSON source, and it works with either a named profile or the default
  legacy-first selection.
- Chromium registrations declare no separate session source, so a Chrome
  profile query cannot recover session state that exists only in memory.

Named helpers (`chrome`, `firefox`, `brave`, `load`, …) and the two-argument
`browser` wrapper are `#[deprecated]` since 0.6.0 in favor of `extract` /
`read` and remain supported through the deprecation window. They are the
compatibility bridge from
[`thewh1teagle/rookie`](https://github.com/thewh1teagle/rookie) and will break
in a later major version.

## One operation, any registered browser

`extract(ExtractRequest::browser(id))` is the current flat, domain-filterable
job for any registered browser. The old `browser(id, domains)` function is a
deprecated wrapper over it. Prefer `read` for an unfiltered, isolation-aware
snapshot; both `read` and `extract` accept `.include_session()` independently
of profile selection.

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
use rookie_cookies::direct_path::{extract_from_path, PathExtractRequest};

fn main() -> rookie_cookies::Result<()> {
    // Sniff: identify the file from its signature. Mozilla, Safari, and IE
    // stores need no credentials; a Chromium store is plaintext-capable only.
    let mozilla = extract_from_path(PathExtractRequest::sniff("/path/to/cookies.sqlite"))?;

    // An encrypted Chromium store needs an explicit strategy. The constructor
    // that names one is platform-gated, because a registry identity means
    // nothing on Windows and a `Local State` file means nothing on Unix.
    #[cfg(unix)]
    let chromium = extract_from_path(
        PathExtractRequest::unix_identity("/path/to/Network/Cookies", "brave")
            .domains(Some(vec!["example.com".to_owned()])),
    )?;
    #[cfg(windows)]
    let chromium = extract_from_path(
        PathExtractRequest::windows_local_state(
            "/path/to/Network/Cookies",
            "/path/to/Local State",
        )
        .domains(Some(vec!["example.com".to_owned()])),
    )?;

    println!("{} {}", mozilla.len(), chromium.len());
    Ok(())
}
```

**There is no `ChromiumPathRequest::new`.** Its default was
`ChromiumCredentialSource::Automatic`, which worked on Unix and could never
succeed on Windows — every Windows request built that way returned
`missing_local_state_file` before attempting extraction. The constructors above
require a strategy that is valid for the target they compile for.

Isolation-carrying output from a path comes from
`from_path(FromPathRequest::new(path)).detailed_cookies()`; `extract_from_path`
is the domain-reducible flat list. That is the same shape rule the browser axis
follows, and it is why there is no `chromium_cookies_from_path_detailed`.

Every 0.6 job function returns `rookie_cookies::Result`, whose error is the
typed `rookie_cookies::Error`:

```rust
match rookie_cookies::direct_path::extract_from_path(
    rookie_cookies::direct_path::PathExtractRequest::sniff("/path/to/Cookies"),
) {
    Ok(cookies) => println!("{}", cookies.len()),
    Err(rookie_cookies::Error::Source(source)) => {
        eprintln!("{} {}", source.kind(), source.code());
    }
    Err(error) => eprintln!("{} {error}", error.code()),
}
```

`Error` has four variants — `Request` (caller input), `Stopped` (timeout,
cancellation, resource ceiling), `Source` (a caller-correctable explicit path
or path option), and `Engine` (discovery, acquisition, decryption, or an
operational path-inspection failure). A corrupt, locked, or otherwise
uninspectable explicit source is `Engine` with code `source_inspection_failed`;
a missing/non-file path or unsupported signature/schema remains `Source`.
`Error::code()` is the stable machine-readable identifier for all four; never
branch on `Display`.

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
    // The eight-field projection is still a free borrow, and still discards
    // isolation -- which is why it is the *inventory* accessor. Reaching the
    // same bytes through a name that promises send-safety goes via `jar()`,
    // which refuses an isolated snapshot instead.
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

`ReadResult::send_view` is **the** send-selection operation, and it takes a
`SendContext`, not a bare URL. A URL alone cannot say which browsing context a
request is made from, so the earlier prerelease `header(url)` had no way to
tell a CHIPS-partitioned cookie from an unpartitioned one — it merged them.

```rust
use rookie_cookies::{read, MethodClass, ReadRequest, SendContext};

fn main() -> rookie_cookies::Result<()> {
    let snapshot = read(ReadRequest::browser("chrome"))?;
    let context = SendContext::url("https://api.example.com/v1/me")
        .top_level_site("https://app.example.com")
        .navigation()
        .method(MethodClass::Safe);
    let view = snapshot.send_view(&context)?;
    for detailed in view.cookies() {
        println!("{}", detailed.cookie.name);
    }
    println!("{}", view.header());
    println!("{} partition misses", view.omitted().partition());
    Ok(())
}
```

`ReadResult::header(&context)` is exactly `send_view(&context)?.header()`. It
renders that one selection rather than repeating the match, so the two can
never disagree, and no binding or CLI subcommand grows a second copy of the
predicate. Use `header` when a request-header string is all you need, and
`send_view` when the selected records or the reason for an empty answer
matter: `SendOmissions` counts every row left out under seven reasons, which
`entries()` always yields in the fixed order `expired`, `not_applicable`,
`same_site`, `partition`, `ancestor_chain_unknown`,
`unparsable_partition_key`, `origin`. Each row is counted exactly once, under
the first stage it failed — and that evaluation order is *not* the
serialization order above: a row is tested for expiry, then the RFC 6265
domain/path/`Secure` filter, then the isolation verdict, then `SameSite`. An
empty selection is a legitimate answer, not an error.

### Isolation selectors

Four selectors beyond `top_level_site`, `user_context_id`, and
`private_browsing_id` describe a context those cannot identify. They are flat
builders on `SendContext`, not a nested selector struct:

| Selector | Argument | What it names |
| --- | --- | --- |
| `ancestor_chain` | `AncestorChain::{SameSite, CrossSite}` | Whether the request's frame tree contains a cross-site ancestor |
| `first_party_domain` | `impl Into<String>` | Firefox `firstPartyDomain` origin attribute |
| `gecko_view_session_context_id` | `impl Into<String>` | Firefox `geckoViewSessionContextId` origin attribute |
| `origin_attributes` | `impl Into<String>` | The verbatim stored Firefox `originAttributes` suffix |

`ancestor_chain` is **derived** when omitted: same-site when the request site
is within `top_level_site` (same scheme, host equal to it or a subdomain of
it), cross-site otherwise. With no `top_level_site` at all the request is
assumed first-party, so the derived chain is `SameSite` — which is safe
because any partitioned row demands `top_level_site`, so that default never
reaches partition matching. Setting it explicitly is how a caller describes an
`A → B → A` embed, whose request site and top-level site are equal even though
an ancestor frame is cross-site. The chain and `SameSite` are coupled through
the same resolved value: an explicit `CrossSite` on a first-party URL also
withholds `SameSite=Lax`/`Strict` rows, exactly as a browser treats that frame
tree. A `SameSite` chain under a *different* top-level site is not honoured —
that is a frame tree no browser can produce — so the resolved chain is
`CrossSite` whenever the two sites do not match.

The Firefox partition port has no selector and no token: it is derived from
the explicit port of the `top_level_site` URL, because that is exactly the
port a Firefox `partitionKey` records.

A snapshot **demands** a selector as soon as one cookie positively observes the
corresponding isolated value — one partitioned cookie is enough, there is no
identity-count threshold. Omitting it is
`RequestError::IncompleteSendContext`, whose `required` names the missing
selectors as stable identifiers. The vocabulary is append-only, and the order
is fixed:

| Selector | Demanded when the snapshot contains |
| --- | --- |
| `top_level_site` | any cookie with a non-empty `top_frame_site_key` **or** `partition_key`, including one whose key no parser in this build understood |
| `user_context_id` | any cookie with `user_context_id == Some(n)`, `n > 0` |
| `private_browsing_id` | any cookie with `private_browsing_id == Some(n)`, `n > 0` |
| `first_party_domain` | any cookie with a stored, non-empty `firstPartyDomain` value |
| `gecko_view_session_context_id` | any cookie with a stored, non-empty `geckoViewSessionContextId` value |
| `origin_attributes` | any cookie carrying an origin-attribute name this build does not recognize, or an unreadable value under one it does |

`ancestor_chain` and the Firefox partition port are never demanded — both are
derived, so there is no selector-shaped hole for a caller to fill. `None` and
`Some(0)` container ids never demand a selector either; gating on them would
make `send_view` unusable against every browser version whose schema lacks
these columns. Once every demanded selector *is* supplied, a value that
matches nothing simply **omits** those rows rather than erroring.
`RequestError::IsolationLossRefused` draws on the same six tokens, so one
handler covers both errors.

**Stated limitations.** `Site` is (scheme, host) — this crate has no
public-suffix list, and does not gain one. `top_level_site` is therefore
*caller-normalized*: supply the registrable site you control, already
normalized. Site membership is same-scheme host equality or subdomain
containment, so `https://cdn.example.com` is within
`top_level_site=https://example.com`, while two sibling subdomains are not
within each other; an IPv4 or IPv6 literal on either side requires exact host
equality rather than a subdomain check. Passing a public suffix
(`https://github.io`) as `top_level_site` would make every host under it
same-site — the known failure mode of that contract, and not something the
crate can detect. A partitioned Chromium row whose store never recorded
`has_cross_site_ancestor` is omitted from every send view rather than assumed
(counted `ancestor_chain_unknown`, and warned as `unknown_ancestor_chain` at
read time); only a store last written by a Chromium older than the
mid-2024 schema that added the column can lack it. A Firefox row
carrying an attribute name this build does not recognize — or a `partitionKey`
it cannot parse, provided the row stored an `originAttributes` value at all —
is *opaque*: it is reachable only by an `origin_attributes` selector equal to
its stored suffix byte-for-byte, and that exact match is necessary rather than
sufficient, since the row still passes through the typed selectors. A row
whose partition key no parser understood and which stored no suffix has
nothing to name, so it is unreachable from any context; a Chromium row is
always in that position, since a Chromium key carries no suffix. Chromium's partition port is identity, not noise: a key naming an
explicit port does not match a `top_level_site` that does not, though
Chromium's own `SchemefulSite` serializes without one, so a key a
current browser writes should not be affected. There is one same-site rule, not a
schemeful/legacy dual mode. A caller needing browser-exact behavior —
storage-access grants, First-Party Sets, nonce-keyed partitions — needs a
browser.

`jar()` / `into_jar()` refuse exactly when that demand list would be
non-empty:

```rust
use rookie_cookies::{read, IsolationLoss, ReadRequest};

fn main() -> rookie_cookies::Result<()> {
    let snapshot = read(ReadRequest::browser("chrome"))?;
    match snapshot.jar() {
        Ok(flat) => println!("{} cookies", flat.len()),
        // Decide explicitly. `IsolationLoss::Allow` returns byte-for-byte
        // what `cookies()` holds; the alternative is to name a browsing
        // context and call `send_view` instead.
        Err(_) => {
            let flat = snapshot.jar_with(IsolationLoss::Allow)?;
            println!("{} cookies, isolation dropped", flat.len());
        }
    }
    Ok(())
}
```

## Session cookies are their own question

```rust
use rookie_cookies::{read, ReadRequest};

fn main() -> rookie_cookies::Result<()> {
    // Earlier 0.6 prereleases reached session cookies only by naming a
    // profile, and always did. Now the two are separate and expressible:
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
session cookies in earlier 0.6 prereleases and no longer does without
`include_session()`. It fails quietly — a smaller list, no error.

## Windows App-Bound (v20)

`AppBoundPolicy` selects, per job, how far the crate may go to recover a
Chrome 127+ App-Bound key:

| Policy | Behavior |
| --- | --- |
| `InjectionOnly` (default) | Unprivileged reflective COM injection into a spawned browser process (Chrome 127+). |
| `Disabled` | No injection, no browser process spawn, no process enumeration, no SYSTEM impersonation. v20 rows are skipped and counted as `decrypt_failed` warnings. |
| `AllowElevatedFallback` | Injection, then elevated SYSTEM impersonation (Chrome 133+). Never a default. |

**Elevation is what changed, not v20 access.** 0.5.9 went straight to
elevated SYSTEM impersonation when injection could not recover the key; the
0.6 job surface stops at unprivileged injection unless a caller writes
`.app_bound(AppBoundPolicy::AllowElevatedFallback)`. The default is
`InjectionOnly` rather than `Disabled` because Chrome has written v20 cookies
on Windows since Chrome 127, so a `Disabled` default would return an empty
list for the common case.

**Injection is not free of consequence.** It spawns a browser process and
writes into it, which endpoint security products can flag. Where that
matters, set `Disabled` explicitly and expect v20 rows to be omitted. The
deprecated v0.5.9 bridge (`chrome`, `browser`, `chromium_based`, …) keeps
`AllowElevatedFallback`, so its 0.5.8 capability is unchanged.

The policy is request-local and immutable once the job starts; it is never
read from the process environment. On non-Windows targets it is a no-op, and
on a build without the `appbound` feature a policy that permits recovery is reported
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

## Migrating to 0.7

Nothing is renamed. `header`, `cookies()`, `into_cookies()`,
`detailed_cookies()`, the free `jar(request)`, and every named helper keep
their names and their signatures. Three things change:

| Change | What breaks | What to do |
| --- | --- | --- |
| `jar` fails closed on isolation loss | Only a call against a snapshot holding a partitioned, containered, or otherwise isolated cookie. The free `jar(request)` now returns `RequestError::IsolationLossRefused` there instead of a flat list that has silently merged two browsing contexts. An unisolated snapshot returns `Ok` exactly as before. | Call `send_view` if you were going to *send* those cookies; call `jar_with`/`into_jar_with` with `IsolationLoss::Allow` if you were not. The opted-in bytes are identical to 0.6's. |
| `header` matches on the full partition identity | A `header` call that previously merged two contexts' cookies now splits them; a row carrying an origin attribute this build does not recognize is omitted until named with `origin_attributes`; a partitioned Chromium row with no stored ancestor bit is omitted rather than sent. | Supply the selectors the error's `required` list names. Use `send_view`'s `omitted()` counts to see what a context excluded and why. |
| Same-site includes subdomains | `SameSite=Lax`/`Strict` rows are now sent for a request host that is a subdomain of `top_level_site`'s host. The rule only widens — nothing that was sent before is withheld now. | Nothing, unless you were relying on literal host equality. Sibling subdomains stay cross-site. |

1. `ReadResult::jar()` / `into_jar()` / `jar_with` / `into_jar_with`,
   `send_view`, `SendView`, `SendOmissions`, `AncestorChain`, and
   `IsolationLoss` are additions; the public-API snapshots for 0.7 add lines
   and remove none.
2. Match `RequestError::IsolationLossRefused` wherever you already match
   `IncompleteSendContext` — they share the `required` vocabulary.
3. Prefer `send_view` over `header` when you need to explain an empty or
   surprising result; `header` alone cannot tell "no cookies here" from
   "everything was excluded".

## Migrate 0.5.6 → 0.6.0

| Area | 0.5.6 / early 0.5.x | 0.6.0 |
| --- | --- | --- |
| Recommended entry | `chrome(None)` / `brave(Some(domains))` | `read(ReadRequest::browser(...).profile(...))` |
| Multi-id store verb | Named helpers only | `extract(ExtractRequest::…)`; `browser(id, domains)` is deprecated |
| Gecko session cookies | Not a first-class policy | Add `.include_session()` to `ReadRequest` or `ExtractRequest`; `.profile(query)` is optional and only selects which profile |
| Path APIs | `*_based`, `any_browser` | `direct_path::{extract_from_path, PathExtractRequest}` (legacy deprecated until 0.7) |
| Errors | Flat `anyhow::Error` | Typed `rookie_cookies::Error` (`Request` / `Stopped` / `Source` / `Engine`) with a stable `code()`. **`rookie_cookies::Result` is no longer `anyhow::Result`**; bridge functions keep `anyhow::Result` and `rookie_cookies::anyhow::Result` still resolves |
| Header / get | Not a job view | `ReadResult::send_view(&SendContext)`, with `header(&SendContext)` rendering it — **no** crate-root `get` or `report` |
| IE helpers | `internet_explorer` / `internet_explorer_based` | Deprecated (ESE native C library; IE discontinued) |

1. For Gecko session import, add `.include_session()`. Add `.profile(...)`
   only when the legacy-first profile is not the one you want.
2. Prefer `extract` for flat domain-filtered lists.
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
