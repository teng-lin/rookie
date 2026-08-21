use regex::Regex;
use reqwest::blocking::Client;
use rookie_cookies::{read, ReadRequest};

fn extract_username(html: &str) -> &str {
  let re = Regex::new(r#"<meta name="user-login" content="(.+)">"#).unwrap();
  if let Some(capture) = re.captures(html) {
    if let Some(content) = capture.get(1) {
      return content.as_str();
    }
  }
  ""
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
  tracing_subscriber::fmt::init();
  let snapshot = read(ReadRequest::browser("brave").profile("Default"))?;
  let client = Client::new();
  let response = client
    .get("https://github.com/")
    .header(
      "User-Agent",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    )
    .header(
      "Cookie",
      snapshot.header(&rookie_cookies::SendContext::url("https://github.com/"))?,
    )
    .send()?;

  let content = response.text()?;
  let username = extract_username(content.as_str());
  match username {
    "" => println!("Not logged in to GitHub"),
    _ => println!("Logged in to GitHub as {username}"),
  };
  Ok(())
}
