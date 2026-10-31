//! Cron schedule parser and scheduler (`tools/cron`).
//!
//! This is a direct port of PocketBase's bundled cron package. The parser
//! intentionally reproduces Go's quirks: `strings.Split` semantics (single
//! space, empty segments are errors), `strconv.Atoi` error strings, and the
//! AND-style matching of all five slots.

use std::collections::BTreeSet;

/// `cron.Moment`: the time components matched against a schedule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Moment {
    pub minute: i64,
    pub hour: i64,
    pub day: i64,
    pub month: i64,
    pub day_of_week: i64,
}

impl Moment {
    /// `cron.NewMoment` for a UTC unix timestamp.
    pub fn from_unix(secs: i64) -> Self {
        let (year, month, day, hour, minute, _, weekday) = civil_from_unix(secs);
        let _ = year;
        Self {
            minute,
            hour,
            day,
            month,
            day_of_week: weekday,
        }
    }
}

/// Days since 1970-01-01 → (year, month, day, hour, minute, second, weekday).
///
/// Howard Hinnant's `civil_from_days`, with Go's weekday numbering (Sunday=0).
fn civil_from_unix(secs: i64) -> (i64, i64, i64, i64, i64, i64, i64) {
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    // 1970-01-01 was a Thursday (Go: 4).
    let weekday = (days + 4).rem_euclid(7);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    (year, m, d, hour, minute, second, weekday)
}

/// `cron.Schedule`: parsed slots for each time component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub minutes: BTreeSet<i64>,
    pub hours: BTreeSet<i64>,
    pub days: BTreeSet<i64>,
    pub months: BTreeSet<i64>,
    pub days_of_week: BTreeSet<i64>,
    raw_expr: String,
}

impl Schedule {
    /// `cron.NewSchedule`.
    pub fn new(cron_expr: &str) -> Result<Self, String> {
        let expanded = match cron_expr {
            "@yearly" | "@annually" => "0 0 1 1 *",
            "@monthly" => "0 0 1 * *",
            "@weekly" => "0 0 * * 0",
            "@daily" | "@midnight" => "0 0 * * *",
            "@hourly" => "0 * * * *",
            other => other,
        };

        // Go: `strings.Split(cronExpr, " ")`; consecutive spaces produce empty
        // segments, which then fail the length check.
        let segments: Vec<&str> = expanded.split(' ').collect();
        if segments.len() != 5 {
            return Err(
                "invalid cron expression - must be a valid macro or to have exactly 5 space separated segments"
                    .to_string(),
            );
        }

        let minutes = parse_cron_segment(segments[0], 0, 59)?;
        let hours = parse_cron_segment(segments[1], 0, 23)?;
        let days = parse_cron_segment(segments[2], 1, 31)?;
        let months = parse_cron_segment(segments[3], 1, 12)?;
        let days_of_week = parse_cron_segment(segments[4], 0, 6)?;

        Ok(Self {
            minutes,
            hours,
            days,
            months,
            days_of_week,
            raw_expr: expanded.to_string(),
        })
    }

    /// `Schedule.IsDue`.
    pub fn is_due(&self, moment: &Moment) -> bool {
        self.minutes.contains(&moment.minute)
            && self.hours.contains(&moment.hour)
            && self.days.contains(&moment.day)
            && self.days_of_week.contains(&moment.day_of_week)
            && self.months.contains(&moment.month)
    }

    /// `Schedule.rawExpr`: the expression after macro expansion.
    pub fn expression(&self) -> &str {
        &self.raw_expr
    }
}

/// Go's `strconv.Atoi`, including its `NumError` message.
fn go_atoi(value: &str) -> Result<i64, String> {
    let bytes = value.as_bytes();
    let mut index = 0;
    let mut negative = false;

    if index < bytes.len() {
        match bytes[index] {
            b'+' => index += 1,
            b'-' => {
                negative = true;
                index += 1;
            }
            _ => {}
        }
    }

    if index == bytes.len() {
        return Err(atoi_error(value, "invalid syntax"));
    }

    let mut parsed: i128 = 0;
    for &byte in &bytes[index..] {
        if !byte.is_ascii_digit() {
            return Err(atoi_error(value, "invalid syntax"));
        }
        parsed = parsed * 10 + i128::from(byte - b'0');
        if parsed > i128::from(i64::MAX) + 1 {
            // Keep accumulating only enough to distinguish overflow.
            parsed = i128::from(i64::MAX) + 2;
        }
    }

    if negative {
        parsed = -parsed;
    }

    if parsed < i128::from(i64::MIN) || parsed > i128::from(i64::MAX) {
        return Err(atoi_error(value, "value out of range"));
    }

    Ok(parsed as i64)
}

fn atoi_error(value: &str, reason: &str) -> String {
    format!(
        "strconv.Atoi: parsing {}: {reason}",
        crate::fields::go_quote(value)
    )
}

/// `cron.parseCronSegment`.
fn parse_cron_segment(segment: &str, min: i64, max: i64) -> Result<BTreeSet<i64>, String> {
    let mut slots = BTreeSet::new();

    for part in segment.split(',') {
        let step_parts: Vec<&str> = part.split('/').collect();

        let step = match step_parts.len() {
            1 => 1,
            2 => {
                let parsed_step = go_atoi(step_parts[1])?;
                if parsed_step < 1 || parsed_step > max {
                    return Err(format!(
                        "invalid segment step boundary - the step must be between 1 and the {max}"
                    ));
                }
                parsed_step
            }
            _ => {
                return Err(
                    "invalid segment step format - must be in the format */n or 1-30/n".to_string(),
                )
            }
        };

        let (range_min, range_max) = if step_parts[0] == "*" {
            (min, max)
        } else {
            let range_parts: Vec<&str> = step_parts[0].split('-').collect();
            match range_parts.len() {
                1 => {
                    if step != 1 {
                        return Err(
                            "invalid segment step - step > 1 could be used only with the wildcard or range format"
                                .to_string(),
                        );
                    }
                    let parsed = go_atoi(range_parts[0])?;
                    if parsed < min || parsed > max {
                        return Err(
                            "invalid segment value - must be between the min and max of the segment"
                                .to_string(),
                        );
                    }
                    (parsed, parsed)
                }
                2 => {
                    let parsed_min = go_atoi(range_parts[0])?;
                    if parsed_min < min || parsed_min > max {
                        return Err(format!(
                            "invalid segment range minimum - must be between {min} and {max}"
                        ));
                    }

                    let parsed_max = go_atoi(range_parts[1])?;
                    if parsed_max < parsed_min || parsed_max > max {
                        return Err(format!(
                            "invalid segment range maximum - must be between {parsed_min} and {max}"
                        ));
                    }
                    (parsed_min, parsed_max)
                }
                _ => {
                    return Err(
                        "invalid segment range format - the range must have 1 or 2 parts".to_string(),
                    )
                }
            }
        };

        let mut i = range_min;
        while i <= range_max {
            slots.insert(i);
            i += step;
        }
    }

    Ok(slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn moment(minute: i64, hour: i64, day: i64, month: i64, day_of_week: i64) -> Moment {
        Moment {
            minute,
            hour,
            day,
            month,
            day_of_week,
        }
    }

    #[test]
    fn macros_expand_to_the_same_slots() {
        for (macro_name, expression) in [
            ("@yearly", "0 0 1 1 *"),
            ("@annually", "0 0 1 1 *"),
            ("@monthly", "0 0 1 * *"),
            ("@weekly", "0 0 * * 0"),
            ("@daily", "0 0 * * *"),
            ("@midnight", "0 0 * * *"),
            ("@hourly", "0 * * * *"),
        ] {
            let parsed = Schedule::new(macro_name).unwrap();
            assert_eq!(parsed, Schedule::new(expression).unwrap());
        }
    }

    #[test]
    fn parser_matches_go_error_messages() {
        let cases = [
            (
                "* * * *",
                "invalid cron expression - must be a valid macro or to have exactly 5 space separated segments",
            ),
            (
                "nope",
                "invalid cron expression - must be a valid macro or to have exactly 5 space separated segments",
            ),
            (
                "JAN * * * *",
                "strconv.Atoi: parsing \"JAN\": invalid syntax",
            ),
            (
                "0 0 * * 7",
                "invalid segment value - must be between the min and max of the segment",
            ),
            (
                "5/15 * * * *",
                "invalid segment step - step > 1 could be used only with the wildcard or range format",
            ),
            (
                "*/0 * * * *",
                "invalid segment step boundary - the step must be between 1 and the 59",
            ),
        ];
        for (expression, expected) in cases {
            assert_eq!(Schedule::new(expression).unwrap_err(), expected);
        }

        assert!(Schedule::new("0 0 31 2 *").is_ok());
        assert!(Schedule::new("1-5/2 * * * *").is_ok());
        assert!(Schedule::new("0 0 * * 6").is_ok());
        assert!(Schedule::new("0 0 * * * ").is_err());
        assert!(Schedule::new(" 0 0 * * *").is_err());
    }

    #[test]
    fn atoi_accepts_signs_and_reports_range_errors() {
        assert_eq!(go_atoi("+5").unwrap(), 5);
        assert_eq!(go_atoi("-5").unwrap(), -5);
        assert_eq!(
            go_atoi("99999999999999999999").unwrap_err(),
            "strconv.Atoi: parsing \"99999999999999999999\": value out of range"
        );
        assert_eq!(
            go_atoi("").unwrap_err(),
            "strconv.Atoi: parsing \"\": invalid syntax"
        );
    }

    #[test]
    fn is_due_requires_all_segments() {
        let schedule = Schedule::new("0 0 1 1 *").unwrap();
        assert!(schedule.is_due(&moment(0, 0, 1, 1, 3)));
        assert!(!schedule.is_due(&moment(1, 0, 1, 1, 3)));
        assert!(!schedule.is_due(&moment(0, 0, 2, 1, 3)));

        let hourly = Schedule::new("0 */6 * * *").unwrap();
        assert!(hourly.is_due(&moment(0, 0, 15, 6, 1)));
        assert!(hourly.is_due(&moment(0, 6, 15, 6, 1)));
        assert!(hourly.is_due(&moment(0, 12, 15, 6, 1)));
        assert!(hourly.is_due(&moment(0, 18, 15, 6, 1)));
        assert!(!hourly.is_due(&moment(0, 5, 15, 6, 1)));
    }

    #[test]
    fn moment_matches_go_weekday_numbering() {
        // 2024-01-01 00:00:00 UTC was a Monday (1).
        let m = Moment::from_unix(1_704_067_200);
        assert_eq!(
            m,
            moment(0, 0, 1, 1, 1),
            "2024-01-01 is a Monday"
        );

        // 2023-12-31 was a Sunday (0).
        let m = Moment::from_unix(1_704_067_200 - 86_400);
        assert_eq!(m.day_of_week, 0);
    }
}
