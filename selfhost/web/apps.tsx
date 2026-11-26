import {ArrowUpRight,AppWindow} from 'lucide-react';
import type {SuiteApp} from '../../app/portal/dashboard';
// The suite home (/apps): one tile per app this person can use. Links open in the same tab.
export default function AppsPage({apps,isAdmin}:{apps:SuiteApp[];isAdmin:boolean}){
 return <section className="suite-apps"><div className="p-heading"><div><p className="eyebrow">HSL SUITE</p><h1>Your apps.</h1><p>One HackSpaceLabs sign-in for every app below.</p></div></div>
 {apps.length?<ul className="suite-app-grid">{apps.map(app=><li key={app.id}><a className="p-panel suite-app-tile" href={app.url}><span className="suite-app-icon" aria-hidden="true"><AppWindow size={20} strokeWidth={1.7}/></span><span className="suite-app-text"><strong>{app.name}</strong><small>{app.description}</small></span><ArrowUpRight size={16} aria-hidden="true"/></a></li>)}</ul>
 :<div className="p-panel suite-app-empty"><h2>No apps yet</h2><p>{isAdmin?'No suite app has an address yet. Set its origin in deployment/.env and rerun the installer.':'Your account doesn’t have access to any app yet. Ask an administrator.'}</p></div>}
 </section>;
}
