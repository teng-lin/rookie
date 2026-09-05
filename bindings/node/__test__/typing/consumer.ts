// Compile-time contract for the 0.7 send-selection surface.
//
// `npm run typecheck` compiles this with `--strict --noEmit`. It is never run
// as a test: nothing here executes, and every assertion is the compiler either
// accepting a call or rejecting one. `@ts-expect-error` is the load-bearing
// half -- tsc fails on an *unused* directive, so a line that stops being an
// error fails the build just as loudly as one that starts being an error.
//
// This is what keeps `index.d.ts` honest about which options belong to which
// job. A field that quietly reappeared on the wrong interface would still pass
// every runtime test that does not happen to pass it.
import type { AncestorChain, SendViewObject } from "../../index";
import { jar, read } from "../../index";

// `allowIsolationLoss` is a jar decision. `read` returns a snapshot that keeps
// every isolated identity, so the flag has nothing to act on there; the
// runtime rejects it, and the type system must too rather than leaving the
// caller to discover that at run time.
async function readRejectsTheJarOnlyOption(): Promise<void> {
  // @ts-expect-error allowIsolationLoss is a JarOptions field, not a ReadOptions one
  await read({ browser: "firefox", allowIsolationLoss: true });
}

// The same option on the job that owns it.
async function jarAcceptsIt(): Promise<void> {
  await jar({ browser: "firefox", allowIsolationLoss: true });
  // The opt-in is optional, and the rest of ReadOptions still applies.
  await jar({ browser: "firefox", profile: "default-release", includeSession: true });
}

// Every selector `SendContextObject` gained in 0.7, in one context object.
async function sendViewTakesEverySelector(): Promise<SendViewObject> {
  const snapshot = await read({ browser: "chrome", profile: "Default" });
  return snapshot.sendView({
    url: "https://example.com/",
    topLevelSite: "https://example.com",
    resource: "navigation",
    method: "safe",
    userContextId: 0,
    privateBrowsingId: 0,
    ancestorChain: "cross_site",
    firstPartyDomain: "",
    geckoViewSessionContextId: "",
    originAttributes: "^futureAttr=1",
    nowEpochSeconds: 1893456000,
  });
}

// A bare URL string is still sugar for `{ url }`, on both entry points.
async function bareUrlSugar(): Promise<string> {
  const snapshot = await read({ browser: "chrome" });
  const view: SendViewObject = snapshot.sendView("https://example.com/");
  return snapshot.header("https://example.com/") + view.header;
}

// `ancestorChain` is the two-value union, not a free string: a typo must not
// compile into a silently derived chain.
const sameSite: AncestorChain = "same_site";
const crossSite: AncestorChain = "cross_site";
// @ts-expect-error the ancestor chain is spelled with underscores, not hyphens
const hyphenated: AncestorChain = "same-site";

// `omitted` carries every reason as a number, and `cookies` keeps the full
// detailed identity rather than the flat eight-field projection. The context
// fields stay nullable: cookie schemas vary by browser, and a caller must not
// be able to read one without saying what it means when the browser had none.
function omissionsAreNumbers(view: SendViewObject): number {
  const partitionKey: string | null = view.cookies[0].context.partitionKey;
  return (
    view.omitted.expired +
    view.omitted.notApplicable +
    view.omitted.sameSite +
    view.omitted.partition +
    view.omitted.ancestorChainUnknown +
    view.omitted.unparsablePartitionKey +
    view.omitted.origin +
    (partitionKey?.length ?? 0)
  );
}

export {
  bareUrlSugar,
  crossSite,
  hyphenated,
  jarAcceptsIt,
  omissionsAreNumbers,
  readRejectsTheJarOnlyOption,
  sameSite,
  sendViewTakesEverySelector,
};
