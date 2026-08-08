import "server-only";

const MAX_SCHEDULE_JSON_BYTES = 4_096;
const MAX_TIMEZONE_BYTES = 100;
const MINUTE_MS = 60_000;
const MAX_LOOKAHEAD_MS = 8 * 24 * 60 * MINUTE_MS;
const SCHEDULE_FIELDS = new Set(["days", "start", "end"]);
const WEEKDAYS = new Map([
  ["Sun", 0],
  ["Mon", 1],
  ["Tue", 2],
  ["Wed", 3],
  ["Thu", 4],
  ["Fri", 5],
  ["Sat", 6],
]);

export type CampaignScheduleEvaluation = {
  allowed: boolean;
  nextAllowedAt: number | null;
};

export type CampaignScheduleInput = {
  scheduleJson: string;
  timeZone: string;
  now: number;
};

type ParsedSchedule =
  | { alwaysAllowed: true }
  | {
      alwaysAllowed: false;
      days: ReadonlySet<number>;
      startMinute: number;
      endMinute: number;
    };

type LocalClock = {
  day: number;
  minute: number;
};

export class CampaignScheduleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CampaignScheduleError";
  }
}

export function evaluateCampaignSchedule(
  input: CampaignScheduleInput,
): CampaignScheduleEvaluation {
  const now = validateTimestamp(input.now);
  const formatter = createLocalClockFormatter(input.timeZone);
  const schedule = parseSchedule(input.scheduleJson);

  if (schedule.alwaysAllowed) {
    return { allowed: true, nextAllowedAt: null };
  }
  if (isAllowed(localClockAt(formatter, now), schedule)) {
    return { allowed: true, nextAllowedAt: null };
  }

  const searchEndsAt = now + MAX_LOOKAHEAD_MS;
  if (!Number.isSafeInteger(searchEndsAt) || Number.isNaN(new Date(searchEndsAt).getTime())) {
    throw new CampaignScheduleError(
      "Campaign schedule timestamp cannot support an eight-day lookahead",
    );
  }

  for (
    let candidate = Math.floor(now / MINUTE_MS) * MINUTE_MS + MINUTE_MS;
    candidate <= searchEndsAt;
    candidate += MINUTE_MS
  ) {
    if (isAllowed(localClockAt(formatter, candidate), schedule)) {
      return { allowed: false, nextAllowedAt: candidate };
    }
  }

  throw new CampaignScheduleError(
    "Campaign schedule has no allowed instant within eight days",
  );
}

function parseSchedule(scheduleJson: string): ParsedSchedule {
  if (
    typeof scheduleJson !== "string" ||
    Buffer.byteLength(scheduleJson, "utf8") > MAX_SCHEDULE_JSON_BYTES
  ) {
    throw new CampaignScheduleError("Campaign schedule JSON is too large");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(scheduleJson);
  } catch {
    throw new CampaignScheduleError("Campaign schedule JSON is malformed");
  }

  if (!isRecord(parsed)) {
    throw new CampaignScheduleError("Campaign schedule must be a JSON object");
  }

  const fields = Object.keys(parsed);
  if (fields.length === 0) return { alwaysAllowed: true };
  if (
    fields.length !== SCHEDULE_FIELDS.size ||
    fields.some((field) => !SCHEDULE_FIELDS.has(field))
  ) {
    throw new CampaignScheduleError(
      "Campaign schedule must contain only days, start, and end",
    );
  }

  const days = parsed.days;
  if (
    !Array.isArray(days) ||
    days.length === 0 ||
    days.length > 7 ||
    days.some((day) => !Number.isInteger(day) || day < 0 || day > 6) ||
    new Set(days).size !== days.length
  ) {
    throw new CampaignScheduleError(
      "Campaign schedule days must be unique integers from 0 through 6",
    );
  }

  const startMinute = parseLocalMinute(parsed.start, "start");
  const endMinute = parseLocalMinute(parsed.end, "end");
  if (startMinute === endMinute) {
    throw new CampaignScheduleError("Campaign schedule window cannot be empty");
  }

  return {
    alwaysAllowed: false,
    days: new Set(days as number[]),
    startMinute,
    endMinute,
  };
}

function parseLocalMinute(value: unknown, field: string): number {
  if (typeof value !== "string") {
    throw new CampaignScheduleError(`Campaign schedule ${field} must use HH:mm`);
  }
  const match = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(value);
  if (!match) {
    throw new CampaignScheduleError(`Campaign schedule ${field} must use HH:mm`);
  }
  return Number(match[1]) * 60 + Number(match[2]);
}

function createLocalClockFormatter(timeZone: string): Intl.DateTimeFormat {
  if (
    typeof timeZone !== "string" ||
    timeZone.length === 0 ||
    timeZone !== timeZone.trim() ||
    Buffer.byteLength(timeZone, "utf8") > MAX_TIMEZONE_BYTES ||
    !/^[A-Za-z0-9._+-]+(?:\/[A-Za-z0-9._+-]+)*$/.test(timeZone)
  ) {
    throw new CampaignScheduleError("Campaign timezone is invalid");
  }

  try {
    return new Intl.DateTimeFormat("en-US", {
      timeZone,
      calendar: "gregory",
      numberingSystem: "latn",
      weekday: "short",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
    });
  } catch {
    throw new CampaignScheduleError("Campaign timezone is invalid");
  }
}

function localClockAt(
  formatter: Intl.DateTimeFormat,
  timestamp: number,
): LocalClock {
  let weekday: string | undefined;
  let hour: string | undefined;
  let minute: string | undefined;
  for (const part of formatter.formatToParts(timestamp)) {
    if (part.type === "weekday") weekday = part.value;
    if (part.type === "hour") hour = part.value;
    if (part.type === "minute") minute = part.value;
  }

  const day = weekday === undefined ? undefined : WEEKDAYS.get(weekday);
  const hourNumber = hour === undefined ? Number.NaN : Number(hour);
  const minuteNumber = minute === undefined ? Number.NaN : Number(minute);
  if (
    day === undefined ||
    !Number.isInteger(hourNumber) ||
    hourNumber < 0 ||
    hourNumber > 23 ||
    !Number.isInteger(minuteNumber) ||
    minuteNumber < 0 ||
    minuteNumber > 59
  ) {
    throw new CampaignScheduleError("Campaign local time could not be evaluated");
  }
  return { day, minute: hourNumber * 60 + minuteNumber };
}

function isAllowed(
  clock: LocalClock,
  schedule: Exclude<ParsedSchedule, { alwaysAllowed: true }>,
): boolean {
  if (schedule.startMinute < schedule.endMinute) {
    return (
      schedule.days.has(clock.day) &&
      clock.minute >= schedule.startMinute &&
      clock.minute < schedule.endMinute
    );
  }

  const previousDay = (clock.day + 6) % 7;
  return (
    (schedule.days.has(clock.day) && clock.minute >= schedule.startMinute) ||
    (schedule.days.has(previousDay) && clock.minute < schedule.endMinute)
  );
}

function validateTimestamp(timestamp: number): number {
  if (
    !Number.isSafeInteger(timestamp) ||
    Number.isNaN(new Date(timestamp).getTime())
  ) {
    throw new CampaignScheduleError("Campaign schedule time must be safe Unix milliseconds");
  }
  return timestamp;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
