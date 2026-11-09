export default function Home() {
  return <>
    <a className="skip" href="#main">Skip to content</a>
    <header className="header wrap">
      <a href="/" className="brand" aria-label="HackSpaceLabs home"><img src="/hackspacelabs-logo.png" alt="HackSpaceLabs — Build, Explore, Connect" /></a>
      <nav aria-label="Main navigation"><a href="#approach">What we do</a><a href="#about">About the lab</a><a href="/login" className="login">Log in <span aria-hidden="true">↗</span></a></nav>
    </header>
    <main id="main">
      <section className="hero wrap">
        <div className="hero-copy"><p className="eyebrow"><span className="dot" /> NETWORKS. HOMES. SOFTWARE.</p><h1>Technology.<br /><em>Made to fit.</em></h1><p className="intro">Networks &amp; security, home automation, and software design.<br />Thoughtfully connected. Built around the way<br className="desktop" /> you live and work.</p><a className="button" href="#approach">Explore what we do <span aria-hidden="true">↘</span></a></div>
        <div className="poster" aria-label="Build. Explore. Connect. The HackSpaceLabs way."><div className="poster-top"><span>HACKSPACELABS</span><span>Ideas into action ↗</span></div><div className="poster-words"><div>Build<span className="orange">.</span></div><div className="outline">Explore<span>.</span></div><div>Connect<span className="teal">.</span></div></div><div className="poster-bottom"><span>A little curiosity.<br />A lot of possibility.</span><div className="swatches" aria-hidden="true"><i/><i/><i/><i/></div></div></div>
      </section>
      <div className="section-divider wrap"><span>IDEAS ARE JUST THE BEGINNING.</span><span>LET’S SEE WHERE THEY GO. ↓</span></div>
      <section className="approach wrap" id="approach"><div className="section-head"><p className="eyebrow">01 / WHAT WE DO</p><h2>Three specialties.<br />One connected approach.</h2><p>From the network behind your devices to the software you use every day, good design starts with how it all fits together.</p></div><div className="principles">
        <article><div className="article-top"><span>01</span><span className="mini-mark orange" aria-hidden="true">＋</span></div><h3>Networks &amp; security.</h3><p>UniFi network design, security cameras, and access control. Thoughtfully planned connections and coverage for the places you live and work.</p><span className="article-foot">UNIFI</span></article>
        <article><div className="article-top"><span>02</span><span className="mini-mark teal" aria-hidden="true">↗</span></div><h3>Home automation.</h3><p>Home automation with Control4, Lutron, and Home Assistant. Bring your devices and everyday routines together around the way you live.</p><span className="article-foot">CONTROL4 · LUTRON · HOME ASSISTANT</span></article>
        <article><div className="article-top"><span>03</span><span className="mini-mark navy" aria-hidden="true">↔</span></div><h3>Software design.</h3><p>Turn a practical need into a considered digital experience. Software designed around real workflows and the people using it.</p><span className="article-foot">BUILT AROUND REAL NEEDS</span></article>
      </div></section>
      <section className="about" id="about"><div className="wrap about-inner"><p className="eyebrow">02 / THE SPIRIT OF THE LAB</p><div><h2>Serious about making.<br /><em>Always open to possibility.</em></h2><p>Technology should earn its place in your day. At HackSpaceLabs, that means thinking about the whole picture: the connections, the experience, and the details that make it work.</p><p>From UniFi networks, cameras, and access control to home automation with Control4, Lutron, and Home Assistant, we choose technology around real needs. The same thinking guides our software design.</p></div></div></section>
      <section className="portal wrap"><div><p className="eyebrow">YOUR SPACE AT HACKSPACELABS</p><h2>Already part of the journey?</h2><p>Your next stop is right here.</p></div><a className="button secondary" href="/login">Go to login <span aria-hidden="true">↗</span></a></section>
    </main>
    <footer className="wrap footer"><span>© {new Date().getFullYear()} HackSpaceLabs</span><span>BUILD <b>•</b> EXPLORE <b>•</b> CONNECT</span><a href="#main">Back to top ↑</a></footer>
  </>;
}
