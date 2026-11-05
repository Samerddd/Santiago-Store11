import { createClient } from '@supabase/supabase-js'

const url = import.meta.env.VITE_SUPABASE_URL
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY

// Optional until Supabase environment variables are configured.
export const supabase = url && anonKey ? createClient(url, anonKey) : null
