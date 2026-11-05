-- Apply this to an existing Santiago Store Supabase project after schema.sql.
-- Removes direct client order writes and restricts product-image storage writes to admins.
alter table public.profiles enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;

drop policy if exists "Customers create own orders" on public.orders;
drop policy if exists "Order items insert for own order" on public.order_items;

create or replace function public.protect_profile_privileges()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if (new.role is distinct from old.role or new.is_banned is distinct from old.is_banned)
     and not public.is_admin() then
    raise exception 'Only an administrator can change account privileges';
  end if;
  return new;
end;
$$;
drop trigger if exists protect_profile_privileges on public.profiles;
create trigger protect_profile_privileges before update on public.profiles
for each row execute procedure public.protect_profile_privileges();

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('product-images', 'product-images', true, 2097152, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

drop policy if exists "Product images are publicly readable" on storage.objects;
drop policy if exists "Admins upload product images" on storage.objects;
drop policy if exists "Admins update product images" on storage.objects;
drop policy if exists "Admins delete product images" on storage.objects;
create policy "Product images are publicly readable" on storage.objects
for select to anon, authenticated using (bucket_id = 'product-images');
create policy "Admins upload product images" on storage.objects
for insert to authenticated with check (bucket_id = 'product-images' and public.is_admin());
create policy "Admins update product images" on storage.objects
for update to authenticated using (bucket_id = 'product-images' and public.is_admin())
with check (bucket_id = 'product-images' and public.is_admin());
create policy "Admins delete product images" on storage.objects
for delete to authenticated using (bucket_id = 'product-images' and public.is_admin());
