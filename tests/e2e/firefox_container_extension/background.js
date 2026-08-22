"use strict";

(async () => {
  const name = "rookie-e2e-container";
  const existing = await browser.contextualIdentities.query({ name });
  const identity =
    existing[0] ||
    (await browser.contextualIdentities.create({
      name,
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
})().catch((error) => console.error("rookie container setup failed", error));
