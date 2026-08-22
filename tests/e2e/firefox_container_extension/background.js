"use strict";

(async () => {
  const pendingName = "rookie-e2e-container";
  const readyName = "rookie-e2e-container-ready";
  const existing = (await browser.contextualIdentities.query({})).filter(
    ({ name }) => name === pendingName || name === readyName,
  );
  const identity =
    existing[0] ||
    (await browser.contextualIdentities.create({
      name: pendingName,
      color: "blue",
      icon: "fingerprint",
    }));
  await browser.cookies.set({
    url: "https://container.rookie.test/",
    name: "rookie_container",
    value: "container-1",
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    expirationDate: Math.trunc(Date.now() / 1000) + 3600,
    storeId: identity.cookieStoreId,
  });
  await browser.contextualIdentities.update(identity.cookieStoreId, {
    name: readyName,
  });
})().catch((error) => console.error("rookie container setup failed", error));
