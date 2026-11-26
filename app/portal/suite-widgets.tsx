'use client';
import {createElement,useEffect,useLayoutEffect,useRef} from 'react';
import type {SuiteApp} from './dashboard';
// The kit's <hsl-app-switcher> and <hsl-user-menu> (ui/suite.js, imported once in selfhost/web/main.tsx).
// Attributes are set through a ref, not as JSX props: React 19 assigns a prop as a property when the element
// has one of that name, and <hsl-app-switcher> has an apps() method that a string would replace.
export const markUrl=new URL('../../ui/mark.svg',import.meta.url).href;
function useAttributes(attributes:Record<string,string>){
 const ref=useRef<HTMLElement>(null);
 const key=JSON.stringify(attributes);
 useLayoutEffect(()=>{const node=ref.current;if(!node)return;for(const [name,value] of Object.entries(attributes)){if(value)node.setAttribute(name,value);else node.removeAttribute(name)}},[key]);
 return ref;
}
// The suite apps this person can use, after this site (id "portal", as the apps list it in HSL_SUITE_APPS).
// With no apps it hides itself.
export function AppSwitcher({apps}:{apps:SuiteApp[]}){
 const list=apps.length?[{id:'portal',name:'HackSpaceLabs',url:'/apps',description:'Your apps and account'},...apps.map(({id,name,url,description})=>({id,name,url,description}))]:[];
 const ref=useAttributes({current:'portal',apps:JSON.stringify(list)});
 return createElement('hsl-app-switcher',{ref});
}
// Name, role line, Profile (the portal's /me), the dark-mode switch and Sign out, which runs onSignOut.
export function UserMenu({name,detail,onSignOut}:{name:string;detail:string;onSignOut?:()=>void}){
 const ref=useAttributes({name,detail,'profile-url':'/me'});
 const signOut=useRef(onSignOut);signOut.current=onSignOut;
 useEffect(()=>{const node=ref.current;if(!node)return;const handle=()=>signOut.current?.();node.addEventListener('hsl-signout',handle);return()=>node.removeEventListener('hsl-signout',handle)},[]);
 return createElement('hsl-user-menu',{ref});
}
