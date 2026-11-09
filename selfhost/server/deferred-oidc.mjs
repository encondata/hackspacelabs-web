import {createOidc} from './oidc.mjs';

// Public DNS and TLS are only needed when authentication is actually requested.
// Share discovery across concurrent requests, and retry after a failed attempt.
export function deferredOidc(settings, discover=createOidc) {
  let pending;
  function client() {
    if (!pending) {
      pending=Promise.resolve().then(()=>discover(settings)).catch(error=>{
        pending=undefined;
        throw error;
      });
    }
    return pending;
  }
  return {
    account:settings.issuer+'/account/',
    async begin(...args){return (await client()).begin(...args)},
    async exchange(...args){return (await client()).exchange(...args)},
    async refresh(...args){return (await client()).refresh(...args)},
    async logout(...args){return (await client()).logout(...args)}
  };
}
