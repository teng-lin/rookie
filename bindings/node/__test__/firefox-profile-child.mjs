import { firefoxProfile, firefoxProfiles, jar } from "../index.js";

const profiles = await firefoxProfiles();
const cookies = await firefoxProfile("work", ["example.test"]);
const jarCookies = await jar({
  browser: "firefox",
  profile: "work",
  includeExpired: true,
});

process.stdout.write(JSON.stringify({ profiles, cookies, jarCookies }));
