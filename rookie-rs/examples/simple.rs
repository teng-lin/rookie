//! Recommended 0.6 entry: `read(ReadRequest::…)`; session cookies are an explicit policy.

fn main() -> rookie_cookies::Result<()> {
  tracing_subscriber::fmt::init();
  let snapshot =
    rookie_cookies::read(rookie_cookies::ReadRequest::browser("chrome").profile("Default"))?;
  for cookie in snapshot.cookies().iter().take(5) {
    println!("{} {}", cookie.domain, cookie.name);
  }
  Ok(())
}
