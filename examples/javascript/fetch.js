import { read } from "rookie-cookies";

const snapshot = await read({ browser: "chrome", profile: "Default" });
const userAgent =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
const res = await fetch("https://github.com/settings/profile", {
  headers: {
    "User-Agent": userAgent,
    Cookie: snapshot.header("https://github.com/settings/profile"),
  },
});
const html = await res.text();
const username =
  html.match(/<a href="\/(.+)" class="btn.+>/)?.[1] ??
  `Not Logged In. Response URL: ${res.url}`;
console.log(`GitHub username: ${username}`);
