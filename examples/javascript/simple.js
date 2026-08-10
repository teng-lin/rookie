import rookieCookies from "rookie-cookies";

for (const cookie of await rookieCookies.brave()) {
  console.log(cookie);
}
