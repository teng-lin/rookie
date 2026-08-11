use anyhow::{anyhow, bail, Context, Result};
use std::{collections::HashMap, sync::Arc};
use zbus::{blocking::Connection, zvariant::ObjectPath, zvariant::Value, Message};

// Keep the legacy KWallet caller ID so existing access grants continue to work.
pub const APP_ID: &str = "rookie";

const LIBSECRET_SCHEMAS: [&str; 2] = [
  "chrome_libsecret_os_crypt_password_v2",
  "chrome_libsecret_os_crypt_password_v1",
];

/// Gets Chromium's password from either Secret Service or KWallet.
///
/// A successful backend is enough to continue, but if every configured
/// backend fails the individual diagnostics are preserved in the returned
/// error. Secret values are never included in those diagnostics.
pub fn get_passwords(unix_crypt_name: &str) -> Result<Vec<String>> {
  get_passwords_with_source(&SystemLinuxKeyringSource, unix_crypt_name)
}

trait LinuxKeyringSource {
  fn libsecret_password(&self, schema: &str, crypt_name: &str) -> Result<String>;
  fn kwallet_password(&self, crypt_name: &str) -> Result<String>;
}

struct SystemLinuxKeyringSource;

impl LinuxKeyringSource for SystemLinuxKeyringSource {
  fn libsecret_password(&self, schema: &str, crypt_name: &str) -> Result<String> {
    get_password_libsecret(schema, crypt_name)
  }

  fn kwallet_password(&self, crypt_name: &str) -> Result<String> {
    get_password_kdewallet(crypt_name)
  }
}

fn get_passwords_with_source<S>(source: &S, crypt_name: &str) -> Result<Vec<String>>
where
  S: LinuxKeyringSource,
{
  let mut passwords = Vec::new();
  let mut failures = Vec::new();

  for schema in LIBSECRET_SCHEMAS {
    match source.libsecret_password(schema, crypt_name) {
      Ok(password) => push_unique(&mut passwords, password),
      Err(error) => failures.push(format!("Secret Service schema '{schema}': {error:#}")),
    }
  }

  match source.kwallet_password(crypt_name) {
    Ok(password) => push_unique(&mut passwords, password),
    Err(error) => failures.push(format!("KWallet: {error:#}")),
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

fn push_unique(values: &mut Vec<String>, value: String) {
  if !values.iter().any(|existing| existing == &value) {
    values.push(value);
  }
}

fn libsecret_call<T>(connection: &Connection, method: &str, args: T) -> zbus::Result<Arc<Message>>
where
  T: serde::ser::Serialize + zvariant::DynamicType,
{
  connection.call_method(
    Some("org.freedesktop.secrets"),
    "/org/freedesktop/secrets",
    Some("org.freedesktop.Secret.Service"),
    method,
    &args,
  )
}

fn kwallet_call<T>(connection: &Connection, method: &str, args: T) -> zbus::Result<Arc<Message>>
where
  T: serde::ser::Serialize + zvariant::DynamicType,
{
  connection.call_method(
    Some("org.kde.kwalletd5"),
    "/modules/kwalletd5",
    Some("org.kde.KWallet"),
    method,
    &args,
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
  fn get_secret(&self, item: &str) -> Result<String>;
}

struct DbusSecretServiceBackend {
  connection: Connection,
}

impl DbusSecretServiceBackend {
  fn connect() -> Result<Self> {
    Ok(Self {
      connection: Connection::session().context("failed to connect to the session D-Bus")?,
    })
  }
}

impl SecretServiceBackend for DbusSecretServiceBackend {
  fn search_items(&self, schema: &str, crypt_name: &str) -> Result<SecretSearchResult> {
    let mut attributes = HashMap::<&str, &str>::new();
    attributes.insert("xdg:schema", schema);
    attributes.insert("application", crypt_name);
    let message = libsecret_call(&self.connection, "SearchItems", &attributes)
      .context("Secret Service SearchItems failed")?;
    let (unlocked, locked): (Vec<ObjectPath>, Vec<ObjectPath>) = message
      .body()
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
    let message =
      libsecret_call(&self.connection, "Unlock", &paths).context("Secret Service Unlock failed")?;
    let (unlocked, prompt): (Vec<ObjectPath>, ObjectPath) = message
      .body()
      .context("Secret Service Unlock returned an invalid response")?;
    Ok(SecretUnlockResult {
      unlocked: unlocked.into_iter().map(|path| path.to_string()).collect(),
      prompt: (prompt.as_str() != "/").then(|| prompt.to_string()),
    })
  }

  fn get_secret(&self, item: &str) -> Result<String> {
    let item_path = ObjectPath::try_from(item)
      .context("Secret Service returned an invalid unlocked item path")?;

    let message = libsecret_call(&self.connection, "OpenSession", &("plain", Value::new("")))
      .context("Secret Service OpenSession failed")?;
    let (_output, session): (Value, ObjectPath) = message
      .body()
      .context("Secret Service OpenSession returned an invalid response")?;

    let message = libsecret_call(
      &self.connection,
      "GetSecrets",
      &(vec![item_path.as_ref()], session),
    )
    .context("Secret Service GetSecrets failed")?;
    type Secret<'a> = (ObjectPath<'a>, Vec<u8>, Vec<u8>, String);
    let secrets: HashMap<ObjectPath, Secret> = message
      .body()
      .context("Secret Service GetSecrets returned an invalid response")?;
    let secret = secrets
      .get(&item_path)
      .ok_or_else(|| anyhow!("Secret Service did not return the requested item"))?;
    String::from_utf8(secret.2.clone()).context("Secret Service password is not valid UTF-8")
  }
}

fn get_password_libsecret(schema: &str, crypt_name: &str) -> Result<String> {
  let backend = DbusSecretServiceBackend::connect()?;
  get_password_libsecret_with_backend(&backend, schema, crypt_name)
}

fn get_password_libsecret_with_backend<B>(
  backend: &B,
  schema: &str,
  crypt_name: &str,
) -> Result<String>
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
  fn read_password(&self, handle: i32, folder: &str, key: &str) -> Result<String>;
  fn close(&self, handle: i32) -> Result<()>;
}

struct DbusKWalletBackend {
  connection: Connection,
}

impl DbusKWalletBackend {
  fn connect() -> Result<Self> {
    Ok(Self {
      connection: Connection::session().context("failed to connect to the session D-Bus")?,
    })
  }
}

fn ensure_kwallet_return_code(operation: &str, code: i32) -> Result<()> {
  if code == 0 {
    Ok(())
  } else {
    bail!("KWallet {operation} failed with return code {code}")
  }
}

impl KWalletBackend for DbusKWalletBackend {
  fn network_wallet(&self) -> Result<String> {
    let message = kwallet_call(&self.connection, "networkWallet", ())
      .context("KWallet networkWallet failed")?;
    message
      .body()
      .context("KWallet networkWallet returned an invalid response")
  }

  fn open(&self, wallet: &str) -> Result<i32> {
    let message = kwallet_call(&self.connection, "open", (wallet, 0_i64, APP_ID))
      .context("KWallet open failed")?;
    let handle: i32 = message
      .body()
      .context("KWallet open returned an invalid response")?;
    if handle < 0 {
      bail!("KWallet open returned invalid handle {handle}");
    }
    Ok(handle)
  }

  fn read_password(&self, handle: i32, folder: &str, key: &str) -> Result<String> {
    let message = kwallet_call(
      &self.connection,
      "readPassword",
      (handle, folder, key, APP_ID),
    )
    .context("KWallet readPassword failed")?;
    message
      .body()
      .context("KWallet readPassword returned an invalid response")
  }

  fn close(&self, handle: i32) -> Result<()> {
    let message = kwallet_call(&self.connection, "close", (handle, false, APP_ID))
      .context("KWallet close failed")?;
    let code: i32 = message
      .body()
      .context("KWallet close returned an invalid response")?;
    ensure_kwallet_return_code("close", code)
  }
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

  fn read_password(&self, folder: &str, key: &str) -> Result<String> {
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

fn get_password_kdewallet(crypt_name: &str) -> Result<String> {
  let backend = DbusKWalletBackend::connect()?;
  get_password_kdewallet_with_backend(&backend, crypt_name)
}

fn get_password_kdewallet_with_backend<B>(backend: &B, crypt_name: &str) -> Result<String>
where
  B: KWalletBackend,
{
  let folder = format!("{} Keys", capitalize(crypt_name));
  let key = format!("{} Safe Storage", capitalize(crypt_name));
  let wallet = backend.network_wallet()?;
  let handle = backend.open(&wallet)?;
  let handle = KWalletHandle::new(backend, handle);
  let password = handle.read_password(&folder, &key)?;
  handle.close()?;
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
  use std::{cell::RefCell, collections::VecDeque};

  struct FakeKeyringSource {
    libsecret: RefCell<VecDeque<Result<String>>>,
    kwallet: RefCell<Option<Result<String>>>,
  }

  impl LinuxKeyringSource for FakeKeyringSource {
    fn libsecret_password(&self, _schema: &str, _crypt_name: &str) -> Result<String> {
      self
        .libsecret
        .borrow_mut()
        .pop_front()
        .expect("one result per schema")
    }

    fn kwallet_password(&self, _crypt_name: &str) -> Result<String> {
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
        Ok("candidate".to_string()),
        Err(anyhow!("old schema unavailable")),
      ])),
      kwallet: RefCell::new(Some(Ok("candidate".to_string()))),
    };

    assert_eq!(
      get_passwords_with_source(&source, "chrome").unwrap(),
      ["candidate"]
    );
  }

  #[derive(Default)]
  struct FakeSecretService {
    search: RefCell<Option<Result<SecretSearchResult>>>,
    unlock: RefCell<Option<Result<SecretUnlockResult>>>,
    secret: RefCell<Option<Result<String>>>,
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

    fn get_secret(&self, item: &str) -> Result<String> {
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
      secret: RefCell::new(Some(Ok("password".to_string()))),
      ..Default::default()
    };

    assert_eq!(
      get_password_libsecret_with_backend(&backend, "schema", "chrome").unwrap(),
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
      secret: RefCell::new(Some(Ok("password".to_string()))),
      ..Default::default()
    };

    assert_eq!(
      get_password_libsecret_with_backend(&backend, "schema", "chrome").unwrap(),
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

  struct FakeKWallet {
    read_result: RefCell<Option<Result<String>>>,
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

    fn read_password(&self, handle: i32, folder: &str, key: &str) -> Result<String> {
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
      read_result: RefCell::new(Some(Ok("password".to_string()))),
      close_result: RefCell::new(Some(Ok(()))),
      calls: RefCell::new(vec![]),
    };

    assert_eq!(
      get_password_kdewallet_with_backend(&backend, "chrome").unwrap(),
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
}
