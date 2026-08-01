import { createClient } from '@supabase/supabase-js'
import { config } from './config.js'

// Service role client for indexer writes (bypasses RLS)
export const supabaseAdmin = createClient(
  config.supabase.url,
  config.supabase.serviceRoleKey,
  { auth: { persistSession: false } }
)

// Anon client for read-only operations (respects RLS)
export const supabasePublic = createClient(
  config.supabase.url,
  config.supabase.anonKey,
  { auth: { persistSession: false } }
)
