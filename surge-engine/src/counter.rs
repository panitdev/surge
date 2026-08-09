use chrono::{DateTime, Utc};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

use crate::schema::rate_limit_window;
use crate::types::AuthError;
use crate::Engine;

/// Result of bumping a windowed counter. Callers derive a retry-after from
/// `window - (now - window_start)`; this module has no opinion on windows,
/// thresholds, or what the key means.
pub struct WindowCount {
    pub count: u32,
    pub window_start: DateTime<Utc>,
}

/// Start of the fixed window containing `now`.
///
/// Built from the whole-second epoch value rather than by subtracting an
/// offset from `now`, which would carry `now`'s sub-second fraction into
/// the result. That matters: `window_start` is half of the upsert's
/// conflict target, so a fractional one is unique per call and every bump
/// inserts a fresh row with `count = 1` — counters that never accumulate
/// and limits that never trip.
fn bucket_start(now: DateTime<Utc>, window_secs: i64) -> DateTime<Utc> {
    let secs = now.timestamp();
    DateTime::from_timestamp(secs - secs.rem_euclid(window_secs), 0).unwrap_or(now)
}

impl Engine {
    /// Bump-and-count an opaque key within a fixed window. Knows nothing
    /// about IPs, actions, or thresholds — the caller composes the key
    /// (e.g. `scope|action|ip` / `scope|action|username`) and owns the
    /// verdict. This is the seam perimeter rate limiters sit behind.
    pub async fn bump_and_count(
        &self,
        key: &str,
        window: std::time::Duration,
    ) -> Result<WindowCount, AuthError> {
        let mut conn = self.conn().await?;
        let window_secs = window.as_secs().max(1) as i64;
        let now = Utc::now();
        let window_start = bucket_start(now, window_secs);

        let count: i32 = diesel::insert_into(rate_limit_window::table)
            .values((
                rate_limit_window::key.eq(key),
                rate_limit_window::window_start.eq(window_start),
                rate_limit_window::count.eq(1),
            ))
            .on_conflict((rate_limit_window::key, rate_limit_window::window_start))
            .do_update()
            .set(rate_limit_window::count.eq(rate_limit_window::count + 1))
            .returning(rate_limit_window::count)
            .get_result(&mut conn)
            .await
            .map_err(|e| AuthError::Internal(e.into()))?;

        Ok(WindowCount {
            count: count as u32,
            window_start,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic `Utc::now()` — never a whole second.
    fn at(secs: i64, nanos: u32) -> DateTime<Utc> {
        DateTime::from_timestamp(secs, nanos).unwrap()
    }

    #[test]
    fn window_start_buckets_are_stable_within_a_window() {
        let t1 = at(1_700_000_005, 123_456_789);
        let t2 = at(1_700_000_035, 987_654_321);
        assert_eq!(bucket_start(t1, 60), bucket_start(t2, 60));
    }

    #[test]
    fn window_start_buckets_differ_across_a_window() {
        let t1 = at(1_700_000_005, 123_456_789);
        let t2 = at(1_700_000_065, 123_456_789);
        assert_ne!(bucket_start(t1, 60), bucket_start(t2, 60));
    }

    /// The bucket is half of the upsert's conflict target. Any sub-second
    /// component makes it unique per call, so every bump inserts its own
    /// row with `count = 1` and no limit ever trips.
    #[test]
    fn window_start_has_no_sub_second_component() {
        let bucket = bucket_start(at(1_700_000_005, 123_456_789), 60);
        assert_eq!(bucket.timestamp_subsec_nanos(), 0);
        assert_eq!(bucket, at(1_699_999_980, 0));
    }

    #[test]
    fn window_start_is_stable_for_two_calls_a_moment_apart() {
        let window_secs = 900;
        let first = bucket_start(at(1_700_000_123, 1), window_secs);
        let second = bucket_start(at(1_700_000_123, 999_999_999), window_secs);
        assert_eq!(first, second);
    }
}
