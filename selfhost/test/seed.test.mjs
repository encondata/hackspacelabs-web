import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {pbkdf2Sync,timingSafeEqual} from 'node:crypto';
test('seeded admin credential matches approved temporary password while requiring its replacement',()=>{
 const realm=JSON.parse(readFileSync(new URL('../../deployment/keycloak/hackspacelabs-realm.json',import.meta.url)));
 const admin=realm.users.find(user=>user.username==='admin');
 const credential=admin.credentials[0];
 const data=JSON.parse(credential.credentialData), secret=JSON.parse(credential.secretData);
 assert.equal(credential.temporary,true);
 assert.equal(credential.value,undefined);
 assert.ok(admin.requiredActions.includes('UPDATE_PASSWORD'));
 assert.ok(realm.passwordPolicy.includes('length(14)'));
 const expected=Buffer.from(secret.value,'base64');
 assert.ok(timingSafeEqual(pbkdf2Sync('123456',Buffer.from(secret.salt,'base64'),data.hashIterations,expected.length,'sha512'),expected));
});
