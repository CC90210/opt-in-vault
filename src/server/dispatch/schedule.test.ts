import {
  CampaignScheduleError,
  evaluateCampaignSchedule,
} from "./schedule";

const WEEKDAYS = JSON.stringify({
  days: [1, 2, 3, 4, 5],
  start: "09:00",
  end: "17:00",
});

function evaluate(scheduleJson: string, timeZone: string, now: number) {
  return evaluateCampaignSchedule({ scheduleJson, timeZone, now });
}

describe("campaign sending-window evaluator", () => {
  it("treats an empty schedule as always allowed", () => {
    expect(
      evaluate("{}", "America/New_York", Date.UTC(2026, 0, 4, 3, 15)),
    ).toEqual({ allowed: true, nextAllowedAt: null });
  });

  it("uses start-inclusive and end-exclusive local weekday windows", () => {
    expect(
      evaluate(WEEKDAYS, "America/New_York", Date.UTC(2026, 0, 5, 14)),
    ).toEqual({ allowed: true, nextAllowedAt: null });
    expect(
      evaluate(WEEKDAYS, "America/New_York", Date.UTC(2026, 0, 5, 21, 59)),
    ).toEqual({ allowed: true, nextAllowedAt: null });

    const atEnd = Date.UTC(2026, 0, 5, 22);
    const result = evaluate(WEEKDAYS, "America/New_York", atEnd);
    expect(result).toEqual({
      allowed: false,
      nextAllowedAt: Date.UTC(2026, 0, 6, 14),
    });
    expect(result.nextAllowedAt).toBeGreaterThan(atEnd);
  });

  it("anchors an overnight window to the local day on which it starts", () => {
    const fridayOvernight = JSON.stringify({
      days: [5],
      start: "22:00",
      end: "02:00",
    });

    expect(
      evaluate(fridayOvernight, "UTC", Date.UTC(2026, 0, 9, 23)),
    ).toEqual({ allowed: true, nextAllowedAt: null });
    expect(
      evaluate(fridayOvernight, "UTC", Date.UTC(2026, 0, 10, 1, 59)),
    ).toEqual({ allowed: true, nextAllowedAt: null });
    expect(
      evaluate(fridayOvernight, "UTC", Date.UTC(2026, 0, 10, 2)),
    ).toEqual({
      allowed: false,
      nextAllowedAt: Date.UTC(2026, 0, 16, 22),
    });
  });

  it("uses IANA timezone transitions rather than a fixed UTC offset", () => {
    const sundayMorning = JSON.stringify({
      days: [0],
      start: "09:00",
      end: "10:00",
    });
    const beforeSpringForward = Date.UTC(2026, 2, 7, 15);

    expect(
      evaluate(sundayMorning, "America/New_York", beforeSpringForward),
    ).toEqual({
      allowed: false,
      nextAllowedAt: Date.UTC(2026, 2, 8, 13),
    });
  });

  it("moves a nonexistent spring-forward start to the first real minute in the window", () => {
    const skippedStart = JSON.stringify({
      days: [0],
      start: "02:30",
      end: "04:00",
    });
    const oneMinuteBeforeJump = Date.UTC(2026, 2, 8, 6, 59);

    expect(
      evaluate(skippedStart, "America/New_York", oneMinuteBeforeJump),
    ).toEqual({
      allowed: false,
      nextAllowedAt: Date.UTC(2026, 2, 8, 7),
    });
  });

  it("finds the second occurrence of a repeated fall-back window", () => {
    const repeatedWindow = JSON.stringify({
      days: [0],
      start: "01:30",
      end: "01:45",
    });
    const afterFirstOccurrence = Date.UTC(2026, 10, 1, 5, 50);

    expect(
      evaluate(repeatedWindow, "America/New_York", afterFirstOccurrence),
    ).toEqual({
      allowed: false,
      nextAllowedAt: Date.UTC(2026, 10, 1, 6, 30),
    });
  });

  it.each([
    "{",
    "null",
    "[]",
    JSON.stringify({ days: [1], start: "09:00" }),
    JSON.stringify({ days: [1], start: "09:00", end: "10:00", extra: true }),
    JSON.stringify({ days: [], start: "09:00", end: "10:00" }),
    JSON.stringify({ days: [1, 1], start: "09:00", end: "10:00" }),
    JSON.stringify({ days: [-1], start: "09:00", end: "10:00" }),
    JSON.stringify({ days: [1.5], start: "09:00", end: "10:00" }),
    JSON.stringify({ days: [1], start: "9:00", end: "10:00" }),
    JSON.stringify({ days: [1], start: "24:00", end: "10:00" }),
    JSON.stringify({ days: [1], start: "09:00", end: "09:00" }),
  ])("rejects malformed or impossible schedules: %s", (scheduleJson) => {
    expect(() => evaluate(scheduleJson, "UTC", Date.UTC(2026, 0, 5))).toThrow(
      CampaignScheduleError,
    );
  });

  it("rejects invalid timezones, unsafe timestamps, and oversized JSON", () => {
    expect(() =>
      evaluate(WEEKDAYS, "Mars/Olympus", Date.UTC(2026, 0, 5)),
    ).toThrow(CampaignScheduleError);
    expect(() => evaluate(WEEKDAYS, " UTC ", Date.UTC(2026, 0, 5))).toThrow(
      CampaignScheduleError,
    );
    expect(() => evaluate(WEEKDAYS, "UTC", Number.NaN)).toThrow(
      CampaignScheduleError,
    );
    expect(() => evaluate(WEEKDAYS, "UTC", 1.5)).toThrow(
      CampaignScheduleError,
    );
    expect(() => evaluate(`${" ".repeat(4_097)}{}`, "UTC", 0)).toThrow(
      /too large/i,
    );
  });

  it("always returns a future next window within eight days", () => {
    const sundayMinute = JSON.stringify({
      days: [0],
      start: "23:58",
      end: "23:59",
    });
    const now = Date.UTC(2026, 0, 5);
    const result = evaluate(sundayMinute, "Pacific/Kiritimati", now);

    expect(result.allowed).toBe(false);
    expect(result.nextAllowedAt).not.toBeNull();
    expect(result.nextAllowedAt!).toBeGreaterThan(now);
    expect(result.nextAllowedAt!).toBeLessThanOrEqual(
      now + 8 * 24 * 60 * 60 * 1_000,
    );
  });
});
