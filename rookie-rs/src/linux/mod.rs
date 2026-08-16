#[cfg(test)]
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use async_io::Timer;
use futures_lite::future;
use std::collections::HashMap;
use std::future::Future;
use zbus::{
  zvariant::{DynamicType, ObjectPath, OwnedObjectPath, OwnedValue, Value},
  Connection, Message,
};

#[cfg(test)]
use crate::common::deadline::SystemClock;
use crate::common::deadline::{BoundaryRuntime, BoundaryStop, Deadline, CLEANUP_GRACE};
use crate::common::secret::SecretString;

mod confidential;
mod zeroizing_dh;
mod zeroizing_hkdf;

// Keep the legacy KWallet caller ID so existing access grants continue to work.
pub const APP_ID: &str = "rookie";

const LIBSECRET_SCHEMAS: [&str; 2] = [
  "chrome_libsecret_os_crypt_password_v2",
  "chrome_libsecret_os_crypt_password_v1",
];

pub(crate) fn get_passwords_with_runtime(
  unix_crypt_name: &str,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<SecretString>> {
  get_passwords_with_source_and_runtime(&SystemLinuxKeyringSource, unix_crypt_name, runtime)
}

trait LinuxKeyringSource {
  fn libsecret_password(
    &self,
    schema: &str,
    crypt_name: &str,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<SecretString>;
  fn kwallet_password(
    &self,
    crypt_name: &str,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<SecretString>;
}

struct SystemLinuxKeyringSource;

impl LinuxKeyringSource for SystemLinuxKeyringSource {
  fn libsecret_password(
    &self,
    schema: &str,
    crypt_name: &str,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<SecretString> {
    get_password_libsecret(schema, crypt_name, runtime)
  }

  fn kwallet_password(
    &self,
    crypt_name: &str,
    runtime: &BoundaryRuntime<'_>,
  ) -> Result<SecretString> {
    get_password_kdewallet(crypt_name, runtime)
  }
}

#[cfg(test)]
fn get_passwords_with_source<S>(source: &S, crypt_name: &str) -> Result<Vec<SecretString>>
where
  S: LinuxKeyringSource,
{
  let runtime = BoundaryRuntime::new(&SystemClock, Deadline::standard());
  get_passwords_with_source_and_runtime(source, crypt_name, &runtime)
}

fn get_passwords_with_source_and_runtime<S>(
  source: &S,
  crypt_name: &str,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Vec<SecretString>>
where
  S: LinuxKeyringSource,
{
  let mut passwords = Vec::new();
  let mut failures = Vec::new();

  for schema in LIBSECRET_SCHEMAS {
    if let Err(stop) = runtime.check() {
      return stop_or_collected(stop, passwords);
    }
    let result = source.libsecret_password(schema, crypt_name, runtime);
    match result {
      Ok(password) => push_unique(&mut passwords, password),
      Err(error) => failures.push(format!("Secret Service schema '{schema}': {error:#}")),
    }
    if let Err(stop) = runtime.check() {
      return stop_or_collected(stop, passwords);
    }
  }

  if let Err(stop) = runtime.check() {
    return stop_or_collected(stop, passwords);
  }
  let result = source.kwallet_password(crypt_name, runtime);
  match result {
    Ok(password) => push_unique(&mut passwords, password),
    Err(error) => failures.push(format!("KWallet: {error:#}")),
  }
  if let Err(stop) = runtime.check() {
    return stop_or_collected(stop, passwords);
  }

  if passwords.is_empty() {
    let diagnostic = format!(
      "all Linux keyring backends failed for crypt_name '{crypt_name}': {}",
      failures.join("; ")
    );
    log::warn!("{diagnostic}");
    bail!(diagnostic);
  }

  for failure in failures {
    log::debug!("Linux keyring candidate source was unavailable: {failure}");
  }
  Ok(passwords)
}

/// A late stop must not erase keys already retrieved: partial keyring
/// results are still usable for decryption, unlike an empty set.
fn stop_or_collected(
  stop: BoundaryStop,
  passwords: Vec<SecretString>,
) -> Result<Vec<SecretString>> {
  if passwords.is_empty() {
    Err(stop.into())
  } else {
    Ok(passwords)
  }
}

fn push_unique(values: &mut Vec<SecretString>, value: SecretString) {
  if !values
    .iter()
    .any(|existing| existing.as_str() == value.as_str())
  {
    values.push(value);
  }
}

fn run_dbus_with_runtime<T, F>(
  runtime: &BoundaryRuntime<'_>,
  operation: &'static str,
  future: F,
) -> Result<T>
where
  F: Future<Output = zbus::Result<T>>,
{
  runtime
    .check()
    .map_err(anyhow::Error::from)
    .with_context(|| format!("{operation} stopped before starting"))?;
  let stop_runtime = runtime.clone();
  let result = future::block_on(future::race(
    async move { future.await.map_err(anyhow::Error::from) },
    async move {
      loop {
        if let Err(stop) = stop_runtime.check() {
          return Err(anyhow::Error::new(stop).context(format!("{operation} stopped")));
        }
        let remaining = stop_runtime
          .deadline
          .remaining(stop_runtime.clock)
          .min(std::time::Duration::from_millis(10));
        Timer::after(remaining).await;
      }
    },
  ));
  // The operation future is polled first by `race`. Re-sample the absolute
  // deadline before accepting its result so a reply observed exactly when the
  // timer becomes due cannot win by poll order.
  runtime
    .check()
    .map_err(anyhow::Error::from)
    .with_context(|| format!("{operation} stopped"))?;
  result
}

fn dbus_method_timeout(runtime: &BoundaryRuntime<'_>) -> Result<std::time::Duration> {
  runtime.check()?;
  let remaining = runtime.deadline.remaining(runtime.clock);
  if remaining.is_zero() {
    return Err(BoundaryStop::TimedOut.into());
  }
  Ok(remaining)
}

fn libsecret_call<T>(
  connection: &Connection,
  method: &'static str,
  args: T,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Message>
where
  T: serde::ser::Serialize + DynamicType,
{
  run_dbus_with_runtime(
    runtime,
    method,
    connection.call_method(
      Some("org.freedesktop.secrets"),
      "/org/freedesktop/secrets",
      Some("org.freedesktop.Secret.Service"),
      method,
      &args,
    ),
  )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KWalletEndpoint {
  version: u8,
  service: &'static str,
  path: &'static str,
}

const KWALLET_ENDPOINTS: [KWalletEndpoint; 2] = [
  KWalletEndpoint {
    version: 6,
    service: "org.kde.kwalletd6",
    path: "/modules/kwalletd6",
  },
  KWalletEndpoint {
    version: 5,
    service: "org.kde.kwalletd5",
    path: "/modules/kwalletd5",
  },
];

fn kwallet_call<T>(
  connection: &Connection,
  endpoint: KWalletEndpoint,
  method: &'static str,
  args: T,
  runtime: &BoundaryRuntime<'_>,
) -> Result<Message>
where
  T: serde::ser::Serialize + DynamicType,
{
  run_dbus_with_runtime(
    runtime,
    method,
    connection.call_method(
      Some(endpoint.service),
      endpoint.path,
      Some("org.kde.KWallet"),
      method,
      &args,
    ),
  )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecretSearchResult {
  unlocked: Vec<String>,
  locked: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SecretUnlockResult {
  unlocked: Vec<String>,
  prompt: Option<String>,
}

trait SecretServiceBackend {
  fn search_items(&self, schema: &str, crypt_name: &str) -> Result<SecretSearchResult>;
  fn unlock(&self, items: &[String]) -> Result<SecretUnlockResult>;
  fn get_secret(&self, item: &str) -> Result<SecretString>;
}

struct DbusSecretServiceBackend<'a> {
  connection: Connection,
  runtime: BoundaryRuntime<'a>,
}

struct DbusConfidentialTransport<'a> {
  connection: &'a Connection,
  runtime: BoundaryRuntime<'a>,
}

impl confidential::Transport for DbusConfidentialTransport<'_> {
  fn open_session(&self, algorithm: &str, client_public_key: Vec<u8>) -> Result<(Vec<u8>, String)> {
    let message = libsecret_call(
      self.connection,
      "OpenSession",
      &(algorithm, Value::new(client_public_key)),
      &self.runtime,
    )
    .context("Secret Service OpenSession failed")?;
    let (output, session): (OwnedValue, OwnedObjectPath) = message
      .body()
      .deserialize()
      .context("Secret Service OpenSession returned an invalid response")?;
    let server_public_key = Vec::<u8>::try_from(output)
      .context("Secret Service OpenSession returned an invalid public key")?;
    Ok((server_public_key, session.to_string()))
  }

  fn get_secret(&self, item: &str, session_path: &str) -> Result<confidential::EncryptedSecret> {
    let item_path = ObjectPath::try_from(item)
      .context("Secret Service returned an invalid unlocked item path")?
      .to_owned();
    let session_path = ObjectPath::try_from(session_path)
      .context("Secret Service returned an invalid confidential session path")?;
    let message = libsecret_call(
      self.connection,
      "GetSecrets",
      &(vec![item_path.clone()], session_path),
      &self.runtime,
    )?;
    type DbusSecret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
    let mut secrets: HashMap<OwnedObjectPath, DbusSecret> = message
      .body()
      .deserialize()
      .context("Secret Service GetSecrets returned an invalid response")?;
    let secret = secrets
      .remove(&item_path)
      .ok_or_else(|| anyhow::anyhow!("Secret Service did not return the requested item"))?;
    Ok(confidential::EncryptedSecret {
      session_path: secret.0.to_string(),
      parameters: secret.1,
      value: secret.2,
    })
  }
}

impl<'a> DbusSecretServiceBackend<'a> {
  fn connect(runtime: &BoundaryRuntime<'a>) -> Result<Self> {
    let remaining =
      dbus_method_timeout(runtime).context("session D-Bus connection timed out before starting")?;
    let builder = zbus::connection::Builder::session()
      .context("failed to resolve the session D-Bus address")?
      .method_timeout(remaining);
    Ok(Self {
      connection: run_dbus_with_runtime(runtime, "session D-Bus connection", builder.build())
        .context("failed to connect to the session D-Bus")?,
      runtime: runtime.clone(),
    })
  }
}

impl SecretServiceBackend for DbusSecretServiceBackend<'_> {
  fn search_items(&self, schema: &str, crypt_name: &str) -> Result<SecretSearchResult> {
    let mut attributes = HashMap::<&str, &str>::new();
    attributes.insert("xdg:schema", schema);
    attributes.insert("application", crypt_name);
    let message = libsecret_call(&self.connection, "SearchItems", &attributes, &self.runtime)
      .context("Secret Service SearchItems failed")?;
    let body = message.body();
    let (unlocked, locked): (Vec<ObjectPath>, Vec<ObjectPath>) = body
      .deserialize()
      .context("Secret Service SearchItems returned an invalid response")?;
    Ok(SecretSearchResult {
      unlocked: unlocked.into_iter().map(|path| path.to_string()).collect(),
      locked: locked.into_iter().map(|path| path.to_string()).collect(),
    })
  }

  fn unlock(&self, items: &[String]) -> Result<SecretUnlockResult> {
    let paths = items
      .iter()
      .map(|path| ObjectPath::try_from(path.as_str()))
      .collect::<std::result::Result<Vec<_>, _>>()
      .context("Secret Service returned an invalid locked item path")?;
    let message = libsecret_call(&self.connection, "Unlock", &paths, &self.runtime)
      .context("Secret Service Unlock failed")?;
    let body = message.body();
    let (unlocked, prompt): (Vec<ObjectPath>, ObjectPath) = body
      .deserialize()
      .context("Secret Service Unlock returned an invalid response")?;
    Ok(SecretUnlockResult {
      unlocked: unlocked.into_iter().map(|path| path.to_string()).collect(),
      prompt: (prompt.as_str() != "/").then(|| prompt.to_string()),
    })
  }

  fn get_secret(&self, item: &str) -> Result<SecretString> {
    // Secret Service's DH mode negotiates
    // `dh-ietf1024-sha256-aes128-cbc-pkcs7`. A failed negotiation is returned
    // to the platform key provider; it must never be retried as a `plain`
    // session because that would put the password on D-Bus in cleartext.
    confidential::get_secret(
      &DbusConfidentialTransport {
        connection: &self.connection,
        runtime: self.runtime.clone(),
      },
      item,
    )
  }
}

fn get_password_libsecret(
  schema: &str,
  crypt_name: &str,
  runtime: &BoundaryRuntime<'_>,
) -> Result<SecretString> {
  let backend = DbusSecretServiceBackend::connect(runtime)?;
  get_password_libsecret_with_backend(&backend, schema, crypt_name)
}

fn get_password_libsecret_with_backend<B>(
  backend: &B,
  schema: &str,
  crypt_name: &str,
) -> Result<SecretString>
where
  B: SecretServiceBackend,
{
  let search = backend.search_items(schema, crypt_name)?;
  if let Some(item) = search.unlocked.first() {
    return backend.get_secret(item);
  }
  if search.locked.is_empty() {
    bail!("Secret Service search returned no matching items");
  }

  let unlock = backend.unlock(&search.locked)?;
  if let Some(item) = unlock.unlocked.first() {
    return backend.get_secret(item);
  }
  if let Some(prompt) = unlock.prompt {
    bail!(
      "Secret Service item is locked and requires an interactive prompt at '{prompt}'; rookie-cookies key retrieval is non-interactive"
    );
  }
  bail!("Secret Service did not unlock any matching item and returned no prompt")
}

trait KWalletBackend {
  fn network_wallet(&self) -> Result<String>;
  fn open(&self, wallet: &str) -> Result<i32>;
  fn read_password(&self, handle: i32, folder: &str, key: &str) -> Result<SecretString>;
  fn close(&self, handle: i32) -> Result<()>;
}

struct DbusKWalletBackend<'a> {
  connection: &'a Connection,
  endpoint: KWalletEndpoint,
  runtime: BoundaryRuntime<'a>,
}

fn ensure_kwallet_return_code(operation: &str, code: i32) -> Result<()> {
  if code == 0 {
    Ok(())
  } else {
    bail!("KWallet {operation} failed with return code {code}")
  }
}

impl KWalletBackend for DbusKWalletBackend<'_> {
  fn network_wallet(&self) -> Result<String> {
    let message = kwallet_call(
      self.connection,
      self.endpoint,
      "networkWallet",
      (),
      &self.runtime,
    )
    .with_context(|| format!("KWallet {} networkWallet failed", self.endpoint.version))?;
    message
      .body()
      .deserialize()
      .context("KWallet networkWallet returned an invalid response")
  }

  fn open(&self, wallet: &str) -> Result<i32> {
    let message = kwallet_call(
      self.connection,
      self.endpoint,
      "open",
      (wallet, 0_i64, APP_ID),
      &self.runtime,
    )
    .with_context(|| format!("KWallet {} open failed", self.endpoint.version))?;
    let handle: i32 = message
      .body()
      .deserialize()
      .context("KWallet open returned an invalid response")?;
    if handle < 0 {
      bail!("KWallet open returned invalid handle {handle}");
    }
    Ok(handle)
  }

  fn read_password(&self, handle: i32, folder: &str, key: &str) -> Result<SecretString> {
    let message = kwallet_call(
      self.connection,
      self.endpoint,
      "readPassword",
      (handle, folder, key, APP_ID),
      &self.runtime,
    )
    .with_context(|| format!("KWallet {} readPassword failed", self.endpoint.version))?;
    message
      .body()
      .deserialize::<String>()
      .map(SecretString::new)
      .context("KWallet readPassword returned an invalid response")
  }

  fn close(&self, handle: i32) -> Result<()> {
    let cleanup_runtime = kwallet_cleanup_runtime(&self.runtime);
    let message = kwallet_call(
      self.connection,
      self.endpoint,
      "close",
      (handle, false, APP_ID),
      &cleanup_runtime,
    )
    .with_context(|| format!("KWallet {} close failed", self.endpoint.version))?;
    let code: i32 = message
      .body()
      .deserialize()
      .context("KWallet close returned an invalid response")?;
    ensure_kwallet_return_code("close", code)
  }
}

fn kwallet_cleanup_runtime<'a>(runtime: &BoundaryRuntime<'a>) -> BoundaryRuntime<'a> {
  // Cleanup must ignore the request stop token so an opened native handle is
  // still closed, but an early cancellation/resource stop must not inherit the
  // request's entire remaining budget. A timeout retains only the unused part
  // of its original absolute cleanup grace.
  let remaining = runtime
    .deadline
    .cleanup_deadline(CLEANUP_GRACE)
    .remaining(runtime.clock)
    .min(CLEANUP_GRACE);
  BoundaryRuntime::new(runtime.clock, Deadline::after(runtime.clock, remaining))
}

struct KWalletHandle<'a, B: KWalletBackend + ?Sized> {
  backend: &'a B,
  handle: i32,
  close_attempted: bool,
}

impl<'a, B: KWalletBackend + ?Sized> KWalletHandle<'a, B> {
  fn new(backend: &'a B, handle: i32) -> Self {
    Self {
      backend,
      handle,
      close_attempted: false,
    }
  }

  fn read_password(&self, folder: &str, key: &str) -> Result<SecretString> {
    self.backend.read_password(self.handle, folder, key)
  }

  fn close(mut self) -> Result<()> {
    self.close_attempted = true;
    self.backend.close(self.handle)
  }
}

impl<B: KWalletBackend + ?Sized> Drop for KWalletHandle<'_, B> {
  fn drop(&mut self) {
    if !self.close_attempted {
      self.close_attempted = true;
      if let Err(error) = self.backend.close(self.handle) {
        log::warn!(
          "Failed to close KWallet handle {} during cleanup: {error:#}",
          self.handle
        );
      }
    }
  }
}

fn get_password_kdewallet(crypt_name: &str, runtime: &BoundaryRuntime<'_>) -> Result<SecretString> {
  let remaining = dbus_method_timeout(runtime)
    .context("session D-Bus connection timed out before KWallet lookup")?;
  let builder = zbus::connection::Builder::session()
    .context("failed to resolve the session D-Bus address")?
    .method_timeout(remaining);
  let connection = run_dbus_with_runtime(runtime, "session D-Bus connection", builder.build())
    .context("failed to connect to the session D-Bus")?;
  get_password_kdewallet_with_fallback(|endpoint| {
    let backend = DbusKWalletBackend {
      connection: &connection,
      endpoint,
      runtime: runtime.clone(),
    };
    get_password_kdewallet_with_backend(&backend, crypt_name)
  })
}

fn get_password_kdewallet_with_fallback<F>(mut attempt: F) -> Result<SecretString>
where
  F: FnMut(KWalletEndpoint) -> Result<SecretString>,
{
  let mut failures = Vec::new();
  for endpoint in KWALLET_ENDPOINTS {
    match attempt(endpoint) {
      Ok(password) if password.is_empty() => failures.push(format!(
        "KWallet {}: readPassword returned no matching entry",
        endpoint.version
      )),
      Ok(password) => return Ok(password),
      Err(error) => failures.push(format!("KWallet {}: {error:#}", endpoint.version)),
    }
  }
  bail!("all KWallet versions failed: {}", failures.join("; "))
}

fn get_password_kdewallet_with_backend<B>(backend: &B, crypt_name: &str) -> Result<SecretString>
where
  B: KWalletBackend,
{
  let folder = format!("{} Keys", capitalize(crypt_name));
  let key = format!("{} Safe Storage", capitalize(crypt_name));
  let wallet = backend.network_wallet()?;
  let handle = backend.open(&wallet)?;
  let handle = KWalletHandle::new(backend, handle);
  let password = handle.read_password(&folder, &key)?;
  if let Err(error) = handle.close() {
    // The password has already been copied out of the wallet. A non-forced
    // close is cleanup, so losing that successful read would be misleading.
    log::warn!("Failed to close KWallet handle after a successful read: {error:#}");
  }
  Ok(password)
}

pub fn capitalize(s: &str) -> String {
  let mut c = s.chars();
  match c.next() {
    None => String::new(),
    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::common::deadline::test_clock::ManualClock;
  use std::{cell::RefCell, collections::VecDeque};

  fn secret(value: &str) -> SecretString {
    SecretString::new(value.to_owned())
  }

  #[test]
  fn zero_dbus_budget_is_a_typed_timeout_after_the_clock_advances() {
    let clock = ManualClock::default();
    let runtime = BoundaryRuntime::new(
      &clock,
      Deadline::after(&clock, std::time::Duration::from_secs(1)),
    );
    runtime.check().expect("budget starts live");
    clock.advance(std::time::Duration::from_secs(1));

    let error = dbus_method_timeout(&runtime).expect_err("advanced deadline is exhausted");
    assert_eq!(
      error.downcast_ref::<BoundaryStop>(),
      Some(&BoundaryStop::TimedOut)
    );
  }

  struct FakeKeyringSource {
    libsecret: RefCell<VecDeque<Result<SecretString>>>,
    kwallet: RefCell<Option<Result<SecretString>>>,
  }

  impl LinuxKeyringSource for FakeKeyringSource {
    fn libsecret_password(
      &self,
      _schema: &str,
      _crypt_name: &str,
      _runtime: &BoundaryRuntime<'_>,
    ) -> Result<SecretString> {
      self
        .libsecret
        .borrow_mut()
        .pop_front()
        .expect("one result per schema")
    }

    fn kwallet_password(
      &self,
      _crypt_name: &str,
      _runtime: &BoundaryRuntime<'_>,
    ) -> Result<SecretString> {
      self
        .kwallet
        .borrow_mut()
        .take()
        .expect("one KWallet result")
    }
  }

  #[test]
  fn all_keyring_failures_are_returned_without_secret_values() {
    let source = FakeKeyringSource {
      libsecret: RefCell::new(VecDeque::from([
        Err(anyhow!("v2 unavailable")),
        Err(anyhow!("v1 locked")),
      ])),
      kwallet: RefCell::new(Some(Err(anyhow!("wallet denied")))),
    };

    let error = get_passwords_with_source(&source, "chrome")
      .expect_err("all providers should fail")
      .to_string();
    assert!(error.contains("all Linux keyring backends failed"));
    assert!(error.contains("v2 unavailable"));
    assert!(error.contains("v1 locked"));
    assert!(error.contains("wallet denied"));
  }

  #[test]
  fn successful_passwords_are_deduplicated_despite_partial_failures() {
    let source = FakeKeyringSource {
      libsecret: RefCell::new(VecDeque::from([
        Ok(secret("candidate")),
        Err(anyhow!("old schema unavailable")),
      ])),
      kwallet: RefCell::new(Some(Ok(secret("candidate")))),
    };

    let passwords = get_passwords_with_source(&source, "chrome").unwrap();
    let passwords: Vec<&str> = passwords.iter().map(|password| password.as_str()).collect();
    assert_eq!(passwords, ["candidate"]);
  }

  struct CancelingKeyringSource {
    stop: crate::common::deadline::CancellationToken,
  }

  impl LinuxKeyringSource for CancelingKeyringSource {
    fn libsecret_password(
      &self,
      _schema: &str,
      _crypt_name: &str,
      _runtime: &BoundaryRuntime<'_>,
    ) -> Result<SecretString> {
      self.stop.cancel();
      Ok(secret("first schema key"))
    }

    fn kwallet_password(
      &self,
      _crypt_name: &str,
      _runtime: &BoundaryRuntime<'_>,
    ) -> Result<SecretString> {
      panic!("a stop after the first schema must end the search before KWallet")
    }
  }

  #[test]
  fn a_late_stop_keeps_a_key_already_retrieved_instead_of_discarding_it() {
    let clock = ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, std::time::Duration::from_secs(1)),
      stop.clone(),
    );
    let source = CancelingKeyringSource { stop };

    let passwords = get_passwords_with_source_and_runtime(&source, "chrome", &runtime)
      .expect("a retrieved key survives a stop that lands right after it");
    let passwords: Vec<&str> = passwords.iter().map(|password| password.as_str()).collect();
    assert_eq!(passwords, ["first schema key"]);
  }

  struct BudgetSource {
    remaining: RefCell<Vec<std::time::Duration>>,
    kwallet_calls: RefCell<usize>,
  }

  impl LinuxKeyringSource for BudgetSource {
    fn libsecret_password(
      &self,
      _schema: &str,
      _crypt_name: &str,
      runtime: &BoundaryRuntime<'_>,
    ) -> Result<SecretString> {
      self
        .remaining
        .borrow_mut()
        .push(runtime.deadline.remaining(runtime.clock));
      let elapsed = if self.remaining.borrow().len() == 1 {
        7
      } else {
        3
      };
      runtime.clock.sleep(std::time::Duration::from_secs(elapsed));
      bail!("scripted provider failure")
    }

    fn kwallet_password(
      &self,
      _crypt_name: &str,
      _runtime: &BoundaryRuntime<'_>,
    ) -> Result<SecretString> {
      *self.kwallet_calls.borrow_mut() += 1;
      bail!("KWallet must not start after the absolute deadline")
    }
  }

  #[test]
  fn fallbacks_share_one_decreasing_absolute_budget_without_wall_clock_sleep() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(10));
    let source = BudgetSource {
      remaining: RefCell::new(Vec::new()),
      kwallet_calls: RefCell::new(0),
    };

    let runtime = BoundaryRuntime::new(&clock, deadline);
    let error = get_passwords_with_source_and_runtime(&source, "chrome", &runtime)
      .expect_err("the second fallback consumes the remaining budget");
    assert!(error
      .downcast_ref::<crate::common::deadline::BoundaryStop>()
      .is_some_and(|stop| *stop == crate::common::deadline::BoundaryStop::TimedOut));
    assert_eq!(
      source.remaining.into_inner(),
      [
        std::time::Duration::from_secs(10),
        std::time::Duration::from_secs(3),
      ]
    );
    assert_eq!(source.kwallet_calls.into_inner(), 0);
    assert_eq!(deadline.remaining(&clock), std::time::Duration::ZERO);
  }

  #[test]
  fn dbus_reply_at_the_exact_deadline_is_timeout_biased_without_wall_clock_sleep() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));
    let runtime = BoundaryRuntime::new(&clock, deadline);

    let error = run_dbus_with_runtime(&runtime, "scripted D-Bus reply", async {
      // The reply future is ready in the same poll that advances the monotonic
      // clock to the deadline. It must not win merely because `race` polls it
      // before the timer future.
      clock.advance(std::time::Duration::from_secs(1));
      Ok::<_, zbus::Error>("reply")
    })
    .expect_err("an exact reply/timeout tie must time out");

    assert!(error.to_string().contains("scripted D-Bus reply stopped"));
    assert!(error
      .downcast_ref::<crate::common::deadline::BoundaryStop>()
      .is_some_and(|stop| *stop == crate::common::deadline::BoundaryStop::TimedOut));
    assert_eq!(deadline.remaining(&clock), std::time::Duration::ZERO);
  }

  #[test]
  fn dbus_wait_observes_cancellation_while_the_provider_is_pending() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(&clock, deadline, stop.clone());

    let error = run_dbus_with_runtime(&runtime, "scripted pending D-Bus call", async move {
      stop.cancel();
      futures_lite::future::pending::<zbus::Result<()>>().await
    })
    .expect_err("cancellation stops a pending provider call");

    assert!(error
      .downcast_ref::<crate::common::deadline::BoundaryStop>()
      .is_some_and(|stop| *stop == crate::common::deadline::BoundaryStop::Cancelled));
  }

  #[test]
  fn dbus_wait_observes_resource_exhaustion_while_the_provider_is_pending() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(1));
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(&clock, deadline, stop.clone());

    let error = run_dbus_with_runtime(&runtime, "scripted pending D-Bus call", async move {
      stop.exhaust_resources();
      futures_lite::future::pending::<zbus::Result<()>>().await
    })
    .expect_err("resource exhaustion stops a pending provider call");

    assert!(error
      .downcast_ref::<crate::common::deadline::BoundaryStop>()
      .is_some_and(|stop| *stop == crate::common::deadline::BoundaryStop::ResourceExhausted));
  }

  #[test]
  fn kwallet_cleanup_after_early_cancellation_is_capped_to_one_grace_window() {
    let clock = ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, std::time::Duration::from_secs(30)),
      stop.clone(),
    );
    clock.advance(std::time::Duration::from_secs(1));
    stop.cancel();

    let cleanup = kwallet_cleanup_runtime(&runtime);

    assert_eq!(cleanup.deadline.remaining(&clock), CLEANUP_GRACE);
    assert!(cleanup.check().is_ok(), "cleanup ignores cancellation");
    clock.advance(CLEANUP_GRACE);
    assert_eq!(
      cleanup.check(),
      Err(crate::common::deadline::BoundaryStop::TimedOut)
    );
  }

  #[test]
  fn kwallet_cleanup_after_resource_exhaustion_is_capped_to_one_grace_window() {
    let clock = ManualClock::default();
    let stop = crate::common::deadline::CancellationToken::default();
    let runtime = BoundaryRuntime::with_stop(
      &clock,
      Deadline::after(&clock, std::time::Duration::from_secs(30)),
      stop.clone(),
    );
    clock.advance(std::time::Duration::from_secs(1));
    stop.exhaust_resources();

    let cleanup = kwallet_cleanup_runtime(&runtime);

    assert_eq!(cleanup.deadline.remaining(&clock), CLEANUP_GRACE);
    assert!(
      cleanup.check().is_ok(),
      "cleanup ignores resource exhaustion"
    );
    clock.advance(CLEANUP_GRACE);
    assert_eq!(
      cleanup.check(),
      Err(crate::common::deadline::BoundaryStop::TimedOut)
    );
  }

  #[test]
  fn kwallet_timeout_cleanup_keeps_only_the_original_remaining_grace() {
    let clock = ManualClock::default();
    let deadline = Deadline::after(&clock, std::time::Duration::from_secs(30));
    let runtime = BoundaryRuntime::new(&clock, deadline);
    clock.advance(std::time::Duration::from_secs(31));

    let cleanup = kwallet_cleanup_runtime(&runtime);

    assert_eq!(
      cleanup.deadline.remaining(&clock),
      std::time::Duration::from_secs(1)
    );
  }

  #[derive(Default)]
  struct FakeSecretService {
    search: RefCell<Option<Result<SecretSearchResult>>>,
    unlock: RefCell<Option<Result<SecretUnlockResult>>>,
    secret: RefCell<Option<Result<SecretString>>>,
    unlock_calls: RefCell<Vec<Vec<String>>>,
    secret_calls: RefCell<Vec<String>>,
  }

  impl SecretServiceBackend for FakeSecretService {
    fn search_items(&self, _schema: &str, _crypt_name: &str) -> Result<SecretSearchResult> {
      self.search.borrow_mut().take().expect("search result")
    }

    fn unlock(&self, items: &[String]) -> Result<SecretUnlockResult> {
      self.unlock_calls.borrow_mut().push(items.to_vec());
      self.unlock.borrow_mut().take().expect("unlock result")
    }

    fn get_secret(&self, item: &str) -> Result<SecretString> {
      self.secret_calls.borrow_mut().push(item.to_string());
      self.secret.borrow_mut().take().expect("secret result")
    }
  }

  #[test]
  fn libsecret_reads_an_already_unlocked_item_without_unlocking_it() {
    let backend = FakeSecretService {
      search: RefCell::new(Some(Ok(SecretSearchResult {
        unlocked: vec!["/unlocked/item".to_string()],
        locked: vec!["/locked/item".to_string()],
      }))),
      secret: RefCell::new(Some(Ok(secret("password")))),
      ..Default::default()
    };

    assert_eq!(
      get_password_libsecret_with_backend(&backend, "schema", "chrome")
        .unwrap()
        .as_str(),
      "password"
    );
    assert!(backend.unlock_calls.borrow().is_empty());
    assert_eq!(backend.secret_calls.borrow().as_slice(), ["/unlocked/item"]);
  }

  #[test]
  fn libsecret_unlocks_locked_candidates_that_need_no_prompt() {
    let backend = FakeSecretService {
      search: RefCell::new(Some(Ok(SecretSearchResult {
        unlocked: vec![],
        locked: vec!["/locked/item".to_string()],
      }))),
      unlock: RefCell::new(Some(Ok(SecretUnlockResult {
        unlocked: vec!["/locked/item".to_string()],
        prompt: None,
      }))),
      secret: RefCell::new(Some(Ok(secret("password")))),
      ..Default::default()
    };

    assert_eq!(
      get_password_libsecret_with_backend(&backend, "schema", "chrome")
        .unwrap()
        .as_str(),
      "password"
    );
    assert_eq!(
      backend.unlock_calls.borrow().as_slice(),
      [vec!["/locked/item".to_string()]]
    );
    assert_eq!(backend.secret_calls.borrow().as_slice(), ["/locked/item"]);
  }

  #[test]
  fn libsecret_reports_when_unlock_requires_an_interactive_prompt() {
    let backend = FakeSecretService {
      search: RefCell::new(Some(Ok(SecretSearchResult {
        unlocked: vec![],
        locked: vec!["/locked/item".to_string()],
      }))),
      unlock: RefCell::new(Some(Ok(SecretUnlockResult {
        unlocked: vec![],
        prompt: Some("/prompt/42".to_string()),
      }))),
      ..Default::default()
    };

    let error = get_password_libsecret_with_backend(&backend, "schema", "chrome")
      .expect_err("interactive prompt must be explicit")
      .to_string();
    assert!(error.contains("requires an interactive prompt"));
    assert!(error.contains("/prompt/42"));
    assert!(backend.secret_calls.borrow().is_empty());
  }

  #[test]
  fn libsecret_reports_when_unlock_returns_no_item_or_prompt() {
    let backend = FakeSecretService {
      search: RefCell::new(Some(Ok(SecretSearchResult {
        unlocked: vec![],
        locked: vec!["/locked/item".to_string()],
      }))),
      unlock: RefCell::new(Some(Ok(SecretUnlockResult {
        unlocked: vec![],
        prompt: None,
      }))),
      ..Default::default()
    };

    let error = get_password_libsecret_with_backend(&backend, "schema", "chrome")
      .expect_err("an empty unlock response must be explicit")
      .to_string();
    assert!(error.contains("did not unlock any matching item"));
    assert!(error.contains("returned no prompt"));
    assert!(backend.secret_calls.borrow().is_empty());
  }

  #[test]
  fn confidential_session_negotiation_failure_remains_a_provider_error() {
    let backend = FakeSecretService {
      search: RefCell::new(Some(Ok(SecretSearchResult {
        unlocked: vec!["/unlocked/item".to_string()],
        locked: vec![],
      }))),
      secret: RefCell::new(Some(Err(anyhow!(
        "Secret Service confidential-session negotiation failed"
      )))),
      ..Default::default()
    };

    let error = get_password_libsecret_with_backend(&backend, "schema", "chrome")
      .expect_err("confidential-session failure must not produce a password")
      .to_string();
    assert!(error.contains("confidential-session negotiation failed"));
    assert_eq!(backend.secret_calls.borrow().as_slice(), ["/unlocked/item"]);
  }

  struct FakeKWallet {
    read_result: RefCell<Option<Result<SecretString>>>,
    close_result: RefCell<Option<Result<()>>>,
    calls: RefCell<Vec<String>>,
  }

  impl KWalletBackend for FakeKWallet {
    fn network_wallet(&self) -> Result<String> {
      self.calls.borrow_mut().push("network_wallet".to_string());
      Ok("wallet-name".to_string())
    }

    fn open(&self, wallet: &str) -> Result<i32> {
      self.calls.borrow_mut().push(format!("open:{wallet}"));
      Ok(42)
    }

    fn read_password(&self, handle: i32, folder: &str, key: &str) -> Result<SecretString> {
      self
        .calls
        .borrow_mut()
        .push(format!("read:{handle}:{folder}:{key}"));
      self.read_result.borrow_mut().take().expect("read result")
    }

    fn close(&self, handle: i32) -> Result<()> {
      self.calls.borrow_mut().push(format!("close:{handle}"));
      self.close_result.borrow_mut().take().expect("close result")
    }
  }

  #[test]
  fn kwallet_closes_the_exact_handle_after_success() {
    let backend = FakeKWallet {
      read_result: RefCell::new(Some(Ok(secret("password")))),
      close_result: RefCell::new(Some(Ok(()))),
      calls: RefCell::new(vec![]),
    };

    assert_eq!(
      get_password_kdewallet_with_backend(&backend, "chrome")
        .unwrap()
        .as_str(),
      "password"
    );
    assert_eq!(
      backend.calls.borrow().as_slice(),
      [
        "network_wallet",
        "open:wallet-name",
        "read:42:Chrome Keys:Chrome Safe Storage",
        "close:42",
      ]
    );
  }

  #[test]
  fn kwallet_preserves_a_successful_read_when_close_fails() {
    let backend = FakeKWallet {
      read_result: RefCell::new(Some(Ok(secret("password")))),
      close_result: RefCell::new(Some(Err(anyhow!("close denied")))),
      calls: RefCell::new(vec![]),
    };

    assert_eq!(
      get_password_kdewallet_with_backend(&backend, "chrome")
        .unwrap()
        .as_str(),
      "password"
    );
    assert_eq!(backend.calls.borrow().last().unwrap(), "close:42");
  }

  #[test]
  fn kwallet_raii_closes_the_exact_handle_when_reading_fails() {
    let backend = FakeKWallet {
      read_result: RefCell::new(Some(Err(anyhow!("read denied")))),
      close_result: RefCell::new(Some(Ok(()))),
      calls: RefCell::new(vec![]),
    };

    let error = get_password_kdewallet_with_backend(&backend, "chrome")
      .expect_err("read should fail")
      .to_string();
    assert!(error.contains("read denied"));
    assert_eq!(backend.calls.borrow().last().unwrap(), "close:42");
  }

  #[test]
  fn kwallet_uses_zero_as_the_success_return_code() {
    assert!(ensure_kwallet_return_code("close", 0).is_ok());
    assert!(ensure_kwallet_return_code("close", 1).is_err());
    assert!(ensure_kwallet_return_code("close", -1).is_err());
  }

  #[test]
  fn kwallet_tries_version_6_before_falling_back_to_version_5() {
    let attempted = RefCell::new(Vec::new());
    let password = get_password_kdewallet_with_fallback(|endpoint| {
      attempted.borrow_mut().push(endpoint.version);
      if endpoint.version == 6 {
        Err(anyhow!("service unavailable"))
      } else {
        Ok(secret("password"))
      }
    })
    .unwrap();

    assert_eq!(password.as_str(), "password");
    assert_eq!(attempted.into_inner(), [6, 5]);
  }

  #[test]
  fn kwallet_does_not_contact_version_5_after_version_6_succeeds() {
    let attempted = RefCell::new(Vec::new());
    let password = get_password_kdewallet_with_fallback(|endpoint| {
      attempted.borrow_mut().push(endpoint.version);
      Ok(secret("password"))
    })
    .unwrap();

    assert_eq!(password.as_str(), "password");
    assert_eq!(attempted.into_inner(), [6]);
  }

  #[test]
  fn kwallet_falls_back_when_version_6_has_no_matching_entry() {
    let attempted = RefCell::new(Vec::new());
    let password = get_password_kdewallet_with_fallback(|endpoint| {
      attempted.borrow_mut().push(endpoint.version);
      if endpoint.version == 6 {
        Ok(secret(""))
      } else {
        Ok(secret("legacy-password"))
      }
    })
    .unwrap();

    assert_eq!(password.as_str(), "legacy-password");
    assert_eq!(attempted.into_inner(), [6, 5]);
  }

  #[test]
  fn kwallet_empty_results_are_reported_as_missing_entries() {
    let error = get_password_kdewallet_with_fallback(|_| Ok(secret("")))
      .expect_err("empty reads from every endpoint must not become a password")
      .to_string();

    assert!(error.contains("KWallet 6: readPassword returned no matching entry"));
    assert!(error.contains("KWallet 5: readPassword returned no matching entry"));
  }
}
