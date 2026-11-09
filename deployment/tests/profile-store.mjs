// Runs only in the disposable CI web container; verifies migration and persistence.
import assert from 'node:assert/strict';
import pg from '/app/node_modules/pg/lib/index.js';
import {createProfileStore} from '/app/server/profile-store.mjs';
const pool=new pg.Pool({connectionString:process.env.DATABASE_URL});
const id='ci-profile-storage-test';
try{
 const first=createProfileStore(pool);await first.update(id,{preferredName:'CI profile',phone:'test'});await first.putAvatar(id,Buffer.from('test-avatar'),'v1');
 const second=createProfileStore(pool);assert.equal((await second.get(id)).preferredName,'CI profile');assert.deepEqual(await second.avatar(id),Buffer.from('test-avatar'));
 await second.update(id,{preferredName:'Updated'});assert.equal((await first.get(id)).avatarVersion,'v1');await second.putAvatar(id,null,null);assert.equal(await first.avatar(id),null);assert.equal((await first.get(id)).preferredName,'Updated');
 console.log('Profile schema migration, stored avatar and profile persistence verified.');
}finally{await pool.query('DELETE FROM public.user_profiles WHERE user_id=$1',[id]);await pool.end()}
