// Lazy schema creation upgrades existing installs without delaying public HTTP startup.
export function createProfileStore(pool){
 let ready;
 async function ensure(){if(!ready)ready=pool.query(`CREATE TABLE IF NOT EXISTS public.user_profiles (
 user_id text PRIMARY KEY, details jsonb NOT NULL DEFAULT '{}'::jsonb,
 avatar bytea, avatar_version text
 )`).catch(error=>{ready=undefined;throw error});await ready}
 return {
  async get(id){await ensure();const {rows}=await pool.query('SELECT details, avatar_version FROM public.user_profiles WHERE user_id=$1',[id]);return rows[0]?{...rows[0].details,avatarVersion:rows[0].avatar_version}:{}},
  async update(id,details){await ensure();await pool.query('INSERT INTO public.user_profiles (user_id,details) VALUES ($1,$2) ON CONFLICT (user_id) DO UPDATE SET details=EXCLUDED.details',[id,details])},
  async avatar(id){await ensure();return (await pool.query('SELECT avatar FROM public.user_profiles WHERE user_id=$1',[id])).rows[0]?.avatar},
  async putAvatar(id,bytes,version){await ensure();await pool.query('INSERT INTO public.user_profiles (user_id,avatar,avatar_version) VALUES ($1,$2,$3) ON CONFLICT (user_id) DO UPDATE SET avatar=EXCLUDED.avatar,avatar_version=EXCLUDED.avatar_version',[id,bytes,version])}
 };
}
