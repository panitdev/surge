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
        let bucket_offset = now.timestamp().rem_euclid(window_secs);
        let window_start = now - chrono::Duration::seconds(bucket_offset);

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

    #[test]
    fn window_start_buckets_are_stable_within_a_window() {
        let window_secs: i64 = 60;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let t1 = base + chrono::Duration::seconds(5);
        let t2 = base + chrono::Duration::seconds(35);
        let bucket = |t: DateTime<Utc>| t - chrono::Duration::seconds(t.timestamp().rem_euclid(window_secs));
        assert_eq!(bucket(t1), bucket(t2));
    }

    #[test]
    fn window_start_buckets_differ_across_a_window() {
        let window_secs: i64 = 60;
        let base = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let t1 = base + chrono::Duration::seconds(5);
        let t2 = base + chrono::Duration::seconds(65);
        let bucket = |t: DateTime<Utc>| t - chrono::Duration::seconds(t.timestamp().rem_euclid(window_secs));
        assert_ne!(bucket(t1), bucket(t2));
    }
}
