-- Santiago Store database schema for Supabase (Postgres).
-- Run in Supabase Dashboard > SQL Editor. Row Level Security is enabled on every table.
create extension if not exists pgcrypto;

create type public.order_status as enum ('processing', 'shipped', 'delivered', 'cancelled');
create type public.payment_method as enum ('cod', 'card');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  phone text,
  address jsonb not null default '{}'::jsonb,
  role text not null default 'customer' check (role in ('customer', 'admin')),
  is_banned boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.categories (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  slug text not null unique,
  description text,
  created_at timestamptz not null default now()
);

create table public.products (
  id uuid primary key default gen_random_uuid(),
  category_id uuid references public.categories(id) on delete set null,
  name text not null,
  slug text not null unique,
  description text not null default '',
  price numeric(12,2) not null check (price >= 0),
  compare_at_price numeric(12,2) check (compare_at_price is null or compare_at_price >= price),
  stock integer not null default 0 check (stock >= 0),
  images text[] not null default '{}',
  is_featured boolean not null default false,
  is_active boolean not null default true,
  rating numeric(2,1) not null default 0 check (rating between 0 and 5),
  review_count integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index products_category_idx on public.products(category_id);
create index products_active_created_idx on public.products(is_active, created_at desc);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  order_number text not null unique default ('SS-' || upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 10))),
  user_id uuid not null references public.profiles(id),
  status public.order_status not null default 'processing',
  payment_method public.payment_method not null default 'cod',
  payment_status text not null default 'pending' check (payment_status in ('pending', 'paid', 'failed', 'refunded')),
  shipping_address jsonb not null,
  subtotal numeric(12,2) not null check (subtotal >= 0),
  shipping_fee numeric(12,2) not null default 0 check (shipping_fee >= 0),
  discount numeric(12,2) not null default 0 check (discount >= 0),
  total numeric(12,2) not null check (total >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index orders_user_created_idx on public.orders(user_id, created_at desc);
create index orders_status_idx on public.orders(status);

create table public.order_items (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null references public.orders(id) on delete cascade,
  product_id uuid references public.products(id) on delete set null,
  product_name text not null,
  unit_price numeric(12,2) not null check (unit_price >= 0),
  quantity integer not null check (quantity > 0),
  created_at timestamptz not null default now()
);

create table public.reviews (
  id uuid primary key default gen_random_uuid(),
  product_id uuid not null references public.products(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  rating integer not null check (rating between 1 and 5),
  body text not null default '',
  created_at timestamptz not null default now(),
  unique(product_id, user_id)
);

create table public.wishlists (
  user_id uuid not null references public.profiles(id) on delete cascade,
  product_id uuid not null references public.products(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key(user_id, product_id)
);

create table public.coupons (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  discount_percent numeric(5,2) not null check (discount_percent > 0 and discount_percent <= 100),
  max_uses integer check (max_uses is null or max_uses > 0),
  uses integer not null default 0,
  starts_at timestamptz,
  expires_at timestamptz,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

create function public.is_admin() returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin' and is_banned = false);
$$;

-- A customer must not be able to promote or unban their own profile through the profile update policy.
create function public.protect_profile_privileges() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if (new.role is distinct from old.role or new.is_banned is distinct from old.is_banned)
     and not public.is_admin() then
    raise exception 'Only an administrator can change account privileges';
  end if;
  return new;
end;
$$;
create trigger protect_profile_privileges before update on public.profiles for each row execute procedure public.protect_profile_privileges();

create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, full_name) values (new.id, coalesce(new.raw_user_meta_data ->> 'full_name', ''));
  return new;
end;
$$;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

alter table public.profiles enable row level security;
alter table public.categories enable row level security;
alter table public.products enable row level security;
alter table public.orders enable row level security;
alter table public.order_items enable row level security;
alter table public.reviews enable row level security;
alter table public.wishlists enable row level security;
alter table public.coupons enable row level security;

create policy "Profiles visible to owner and admins" on public.profiles for select to authenticated using (id = auth.uid() or public.is_admin());
create policy "Customers update own profile" on public.profiles for update to authenticated using (id = auth.uid() or public.is_admin()) with check (id = auth.uid() or public.is_admin());
create policy "Categories readable by everyone" on public.categories for select to anon, authenticated using (true);
create policy "Admins manage categories" on public.categories for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "Active products are public" on public.products for select to anon, authenticated using (is_active or public.is_admin());
create policy "Admins manage products" on public.products for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "Customers view own orders" on public.orders for select to authenticated using (user_id = auth.uid() or public.is_admin());
create policy "Admins update orders" on public.orders for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy "Order items visible to owner or admin" on public.order_items for select to authenticated using (exists(select 1 from public.orders o where o.id = order_id and (o.user_id = auth.uid() or public.is_admin())));
create policy "Reviews are public" on public.reviews for select to anon, authenticated using (true);
create policy "Customers write own reviews" on public.reviews for insert to authenticated with check (user_id = auth.uid());
create policy "Customers update own reviews" on public.reviews for update to authenticated using (user_id = auth.uid() or public.is_admin()) with check (user_id = auth.uid() or public.is_admin());
create policy "Customers delete own reviews" on public.reviews for delete to authenticated using (user_id = auth.uid() or public.is_admin());
create policy "Customers manage own wishlist" on public.wishlists for all to authenticated using (user_id = auth.uid() or public.is_admin()) with check (user_id = auth.uid() or public.is_admin());
create policy "Active coupons public for validation" on public.coupons for select to anon, authenticated using (is_active = true);
create policy "Admins manage coupons" on public.coupons for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- Product images are public storefront assets; only verified admins can upload, replace, or delete them.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('product-images', 'product-images', true, 2097152, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;
create policy "Product images are publicly readable" on storage.objects for select to anon, authenticated using (bucket_id = 'product-images');
create policy "Admins upload product images" on storage.objects for insert to authenticated with check (bucket_id = 'product-images' and public.is_admin());
create policy "Admins update product images" on storage.objects for update to authenticated using (bucket_id = 'product-images' and public.is_admin()) with check (bucket_id = 'product-images' and public.is_admin());
create policy "Admins delete product images" on storage.objects for delete to authenticated using (bucket_id = 'product-images' and public.is_admin());
