// Recommended 0.6 entry. Pass profile for session cookies. Always await.
import { read } from "rookie-cookies";

const snapshot = await read({ browser: "chrome", profile: "Default" });
console.log(snapshot.cookies.length, snapshot.warnings);
for (const cookie of snapshot.cookies.slice(0, 5)) {
  console.log(cookie.domain, cookie.name);
}
