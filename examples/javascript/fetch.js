import rookieCookies from "rookie-cookies";
import { createCookieHeader } from "./cookie-header.js";

async function createHeaders() {
  // Get all GitHub cookies from all browsers
  const cookies = await rookieCookies.load(["github.com"]);
  // Create cookie header
  const cookie = createCookieHeader(cookies);
  const userAgent =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
  return {
    "User-Agent": userAgent,
    Cookie: cookie,
  };
}

const headers = await createHeaders();
const res = await fetch("https://github.com/settings/profile", { headers });
const html = await res.text();
// Parse username from HTML
const username =
  html.match(/<a href="\/(.+)" class="btn.+>/)?.[1] ??
  `Not Logged In. Response URL: ${res.url}`;
console.log(`GitHub username: ${username}`);
