'use client';
import {useEffect,useRef} from 'react';
import type {SuiteApp} from './dashboard';
// The kit's <hsl-app-switcher> and <hsl-user-menu> (ui/suite.js, imported once in selfhost/web/main.tsx;
// their JSX attributes are declared in ui/hsl-suite.d.ts). Attributes are strings.
export const markUrl=new URL('../../ui/mark.svg',import.meta.url).href;
// The suite apps this person can use, after this site (id "portal", as the apps list it in HSL_SUITE_APPS).
// With no apps it hides itself. Names only, no descriptions: the apps' own switchers get id|name|url from
// HSL_SUITE_APPS, and every site's switcher should look the same.
export function AppSwitcher({apps}:{apps:SuiteApp[]}){
 const list=apps.length?[{id:'portal',name:'HackSpaceLabs',url:'/apps'},...apps.map(({id,name,url})=>({id,name,url}))]:[];
 return <hsl-app-switcher current="portal" apps={JSON.stringify(list)}/>;
}
// Name, photo (if any), role line, Profile (the portal's /me), the dark-mode switch and Sign out, which
// runs onSignOut.
export function UserMenu({name,detail,avatarUrl,onSignOut}:{name:string;detail:string;avatarUrl?:string;onSignOut?:()=>void}){
 const ref=useRef<HTMLElement>(null);const signOut=useRef(onSignOut);signOut.current=onSignOut;
 useEffect(()=>{const node=ref.current;if(!node)return;const handle=()=>signOut.current?.();node.addEventListener('hsl-signout',handle);return()=>node.removeEventListener('hsl-signout',handle)},[]);
 return <hsl-user-menu ref={ref} name={name} detail={detail} avatar-url={avatarUrl||''} profile-url="/me"/>;
}
