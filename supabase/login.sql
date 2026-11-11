-- Kart Kaos: login med navn + adgangskode.
-- Køres én gang i Supabase → SQL Editor. Kan køres igen uden at gå i stykker.

create extension if not exists pgcrypto with schema extensions;

alter table public.players add column if not exists pw_hash text;
alter table public.players add column if not exists login_fails integer not null default 0;
alter table public.players add column if not exists login_locked_until timestamptz;

-- Ekstra sikring: ingen direkte adgang til players (leaderboard-viewet læser stadig som ejer).
alter table public.players enable row level security;
alter view public.leaderboard set (security_invoker = off);

-- Sæt eller skift adgangskode. Kræver spillerens id + secret (som browseren allerede har).
create or replace function public.set_password(p_id uuid, p_secret text, p_password text)
returns boolean
language plpgsql security definer
set search_path = public, extensions
as $$
begin
  if p_password is null or char_length(p_password) < 6 or char_length(p_password) > 72 then
    raise exception 'Adgangskoden skal være 6-72 tegn';
  end if;
  update players set pw_hash = crypt(p_password, gen_salt('bf', 10)), login_fails = 0, login_locked_until = null
  where id = p_id and secret = p_secret;
  return found;
end $$;

-- Log ind med navn + adgangskode. Returnerer id, secret og navn ved succes.
-- 5 forkerte forsøg i træk låser navnet i 5 minutter.
create or replace function public.login_player(p_name text, p_password text)
returns json
language plpgsql security definer
set search_path = public, extensions
as $$
declare r players%rowtype;
begin
  select * into r from players
  where lower(players.name) = lower(trim(p_name))
  order by (players.name = trim(p_name)) desc
  limit 1;
  if not found or r.pw_hash is null then
    perform pg_sleep(0.3);
    return json_build_object('ok', false, 'reason', 'wrong');
  end if;
  if r.login_locked_until is not null and r.login_locked_until > now() then
    return json_build_object('ok', false, 'reason', 'locked',
      'seconds', ceil(extract(epoch from r.login_locked_until - now())));
  end if;
  if r.pw_hash <> crypt(p_password, r.pw_hash) then
    update players set
      login_fails = case when login_fails + 1 >= 5 then 0 else login_fails + 1 end,
      login_locked_until = case when login_fails + 1 >= 5 then now() + interval '5 minutes' else null end
    where id = r.id;
    return json_build_object('ok', false, 'reason', 'wrong');
  end if;
  update players set login_fails = 0, login_locked_until = null where id = r.id;
  return json_build_object('ok', true, 'id', r.id, 'secret', r.secret, 'name', r.name);
end $$;

revoke all on function public.set_password(uuid, text, text) from public;
revoke all on function public.login_player(text, text) from public;
grant execute on function public.set_password(uuid, text, text) to anon, authenticated;
grant execute on function public.login_player(text, text) to anon, authenticated;
