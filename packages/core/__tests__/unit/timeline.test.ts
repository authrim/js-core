import { describe, expect, it } from "vitest";
import { EventTimeline } from "../../src/debug/timeline.js";

describe("EventTimeline", () => {
  it("redacts Native SSO device_secret fields", () => {
    const timeline = new EventTimeline();

    timeline.record("native_sso.exchange", {
      device_secret: "device-secret-12345678901234567890",
      actor_token: "actor-token-12345678901234567890",
      subject_token: "subject-token-12345678901234567890",
      status: "started",
    });

    const entry = timeline.getRecent()[0];

    expect(entry.data).toMatchObject({
      hasDevice_secret: true,
      device_secret: "[REDACTED]",
      hasActor_token: true,
      actor_token: "[REDACTED]",
      hasSubject_token: true,
      subject_token: "[REDACTED]",
      status: "started",
    });
  });

  it("redacts Native SSO token exchange URL parameters in aggressive mode", () => {
    const timeline = new EventTimeline({ redactLevel: "aggressive" });

    timeline.record("http.request", {
      url: "https://auth.example.com/token?actor_token=actor-secret&device_secret=device-secret&status=active",
    });

    const entry = timeline.getRecent()[0];
    const data = entry.data as { url: string };

    expect(data.url).toContain("actor_token=%5BREDACTED%5D");
    expect(data.url).toContain("device_secret=%5BREDACTED%5D");
    expect(data.url).toContain("status=active");
  });
});
