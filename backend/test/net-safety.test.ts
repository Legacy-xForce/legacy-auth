import { describe, expect, test } from "bun:test";
import { assertPublicTarget, internalTargetProblem, isInternalAddress } from "../src/oidc/net-safety.ts";

describe("isInternalAddress", () => {
  test.each([
    // loopback, private, link-local (incl. cloud metadata), carrier-grade NAT, reserved
    ["0.0.0.0", true],
    ["0.1.2.3", true],
    ["10.0.0.1", true],
    ["10.255.255.255", true],
    ["100.64.0.1", true],
    ["100.127.255.255", true],
    ["100.128.0.1", false],
    ["127.0.0.1", true],
    ["127.255.255.254", true],
    ["169.254.169.254", true],
    ["172.15.255.255", false],
    ["172.16.0.1", true],
    ["172.31.255.255", true],
    ["172.32.0.1", false],
    ["192.0.0.5", true],
    ["192.0.2.1", false],
    ["192.168.0.1", true],
    ["192.169.0.1", false],
    ["198.18.0.1", true],
    ["198.19.255.255", true],
    ["198.20.0.1", false],
    ["224.0.0.1", true],
    ["239.255.255.255", true],
    ["240.0.0.1", true],
    ["255.255.255.255", true],
    // public
    ["1.1.1.1", false],
    ["8.8.8.8", false],
    ["93.184.216.34", false],
    ["203.0.113.5", false],
  ])("IPv4 %s -> %p", (address, expected) => {
    expect(isInternalAddress(address)).toBe(expected);
  });

  test.each([
    ["::", true],
    ["::1", true],
    ["[::1]", true],
    ["fc00::1", true],
    ["fd12:3456::1", true],
    ["fe80::1", true],
    ["febf::1", true],
    ["fec0::1", false],
    ["ff02::1", true],
    ["::ffff:10.0.0.1", true],
    ["::ffff:127.0.0.1", true],
    ["::ffff:8.8.8.8", false],
    ["2001:4860:4860::8888", false],
    ["2606:4700:4700::1111", false],
  ])("IPv6 %s -> %p", (address, expected) => {
    expect(isInternalAddress(address)).toBe(expected);
  });

  test("a name is not an address", () => {
    expect(isInternalAddress("example.com")).toBe(false);
    expect(isInternalAddress("not an ip")).toBe(false);
  });
});

describe("internalTargetProblem", () => {
  test.each([
    "http://localhost/x",
    "https://LOCALHOST/x",
    "https://api.localhost/x",
    "https://printer.local/x",
    "https://db.internal/x",
    "https://nas.lan/x",
    "https://router.home.arpa/x",
    "http://127.0.0.1:8080/x",
    "http://[::1]/x",
    "https://10.1.2.3/x",
    "https://169.254.169.254/latest/meta-data",
    "https://192.168.1.1/x",
  ])("refuses %s", (url) => {
    expect(internalTargetProblem(url)).toBeString();
  });

  test.each(["https://app.example.test/x", "https://calendar.legacy-group.tech/auth/backchannel-logout", "https://203.0.113.5/x", "https://localhost.example.com/x"])(
    "allows %s",
    (url) => {
      expect(internalTargetProblem(url)).toBeNull();
    }
  );

  test("says it is not a URL when it is not", () => {
    expect(internalTargetProblem("not a url")).toContain("not a valid URL");
  });
});

describe("assertPublicTarget", () => {
  const resolvesTo = (...addresses: string[]) => async () => addresses.map((address) => ({ address }));

  test("accepts a name that resolves only to public addresses", async () => {
    await expect(assertPublicTarget("https://app.example.test/bc", resolvesTo("203.0.113.5", "2606:4700:4700::1111"))).resolves.toBeUndefined();
  });

  test("refuses a name that resolves to an internal address (DNS pointed inwards)", async () => {
    await expect(assertPublicTarget("https://app.example.test/bc", resolvesTo("10.0.0.7"))).rejects.toThrow(/resolves to the internal address 10\.0\.0\.7/);
    await expect(assertPublicTarget("https://app.example.test/bc", resolvesTo("127.0.0.1"))).rejects.toThrow(/internal address/);
  });

  test("refuses when any one of several answers is internal", async () => {
    await expect(assertPublicTarget("https://app.example.test/bc", resolvesTo("203.0.113.5", "192.168.0.9"))).rejects.toThrow(/192\.168\.0\.9/);
  });

  test("refuses an internal name without resolving it at all", async () => {
    let resolved = false;
    await expect(
      assertPublicTarget("https://db.internal/bc", async () => {
        resolved = true;
        return [{ address: "203.0.113.5" }];
      })
    ).rejects.toThrow(/local or private name/);
    expect(resolved).toBe(false);
  });

  test("checks an IP literal as written, with no lookup", async () => {
    const never = async () => {
      throw new Error("must not resolve a literal");
    };
    await expect(assertPublicTarget("https://203.0.113.5/bc", never)).resolves.toBeUndefined();
    await expect(assertPublicTarget("https://10.0.0.1/bc", never)).rejects.toThrow(/internal address/);
    await expect(assertPublicTarget("https://[::1]/bc", never)).rejects.toThrow(/internal address/);
  });

  test("a name that does not resolve is an error, not a pass", async () => {
    await expect(
      assertPublicTarget("https://nowhere.example.test/bc", async () => {
        throw new Error("ENOTFOUND");
      })
    ).rejects.toThrow("ENOTFOUND");
  });
});
