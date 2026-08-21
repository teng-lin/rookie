import { browserProfiles, browserReport } from "../index.js";

// Runs inside the fixture environment the parent test builds. Reporting the
// observed `typeof` of every leaf from this process is the point: a BigInt
// counter would be lost or throw once the result is serialized below.
function leafTypes(value, types = new Set()) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      leafTypes(entry, types);
    }
  } else if (value !== null && typeof value === "object") {
    for (const entry of Object.values(value)) {
      leafTypes(entry, types);
    }
  } else {
    types.add(typeof value);
  }
  return types;
}

const profiles = await browserProfiles("firefox");
const work = profiles.find(({ profile }) => profile.displayName === "work");
const report = await browserReport({
  browserId: "firefox",
  profileId: work.profile.profileId,
  domains: ["example.test"],
});

process.stdout.write(
  JSON.stringify({
    profiles,
    report,
    leafTypes: [...leafTypes(report)].sort(),
  }),
);
