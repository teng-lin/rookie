const COOKIE_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const COOKIE_VALUE = /^[\u0021\u0023-\u002B\u002D-\u003A\u003C-\u005B\u005D-\u007E]*$/u;

/**
 * Build an RFC 6265 Cookie header without changing the values stored by the
 * browser. In particular, percent escapes are already part of the cookie
 * value and must not be decoded before sending them back to the server.
 */
export function createCookieHeader(cookies) {
  return cookies
    .map(({ name, value }) => {
      if (!COOKIE_NAME.test(name)) {
        throw new TypeError(`Unsafe cookie name: ${JSON.stringify(name)}`);
      }

      const rawValue = value ?? "";
      if (!COOKIE_VALUE.test(rawValue)) {
        throw new TypeError(`Unsafe value for cookie ${JSON.stringify(name)}`);
      }

      return `${name}=${rawValue}`;
    })
    .join("; ");
}
