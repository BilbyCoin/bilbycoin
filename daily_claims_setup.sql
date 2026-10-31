CREATE TABLE IF NOT EXISTS public.daily_claims (
    user_id BIGINT PRIMARY KEY REFERENCES public.users(user_id) ON DELETE CASCADE,
    claimed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS daily_claims_claimed_at_idx
ON public.daily_claims (claimed_at);
