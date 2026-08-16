fn main() {
  tracing_subscriber::fmt::init();
  let cookies = rookie_cookies::browser("chrome", None).unwrap();
  for cookie in cookies {
    println!("{:?}", cookie);
  }
}
