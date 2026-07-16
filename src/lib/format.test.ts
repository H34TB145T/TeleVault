import { describe, expect, it } from "vitest";
import { categoryForName, formatBytes, formatEta } from "./format";

describe("file presentation helpers", () => {
  it("categorizes common files without case sensitivity", () => {
    expect(categoryForName("Holiday.JPEG")).toBe("Photos");
    expect(categoryForName("backup.tar.gz")).toBe("Archives");
    expect(categoryForName("README")).toBe("Other");
  });

  it("formats storage values and transfer times", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(5 * 1024 ** 3)).toBe("5.0 GB");
    expect(formatEta(90)).toBe("2 min");
  });
});
