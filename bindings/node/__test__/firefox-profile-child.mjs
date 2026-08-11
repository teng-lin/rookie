import { firefoxProfile, firefoxProfiles } from "../index.js";

const profiles = await firefoxProfiles();
const cookies = await firefoxProfile("work", ["example.test"]);

process.stdout.write(JSON.stringify({ profiles, cookies }));
