import test from "ava";

import rookieCookies from "../index.js";

test("a native worker panic rejects its Promise without aborting Node", async (t) => {
  t.is(typeof rookieCookies.__testWorkerPanic, "function");

  const promise = rookieCookies.__testWorkerPanic();
  t.true(promise instanceof Promise);
  const error = await t.throwsAsync(promise);
  t.regex(error.message, /cookie extraction worker panicked: forced Node worker panic/);
});
