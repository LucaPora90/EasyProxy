/* Shared top navigation for every EasyProxy page.
   Injected by static/ep-nav.js so all templates stay in sync. */
(function () {
    const groups = [
        [
            {label: 'Playlist Builder', href: '/builder', paths: ['/builder', '/playlist/builder']},
            {label: 'URL Generator', href: '/url-generator'},
            {label: 'DVR Recordings', href: '/recordings'},
        ],
        [
            {label: 'Admin', href: '/admin'},
            {label: 'TorProxy', href: '/admin/torproxy'},
            {label: 'NordVPN', href: '/admin/nordvpn'},
            {label: 'Custom WireGuard', href: '/admin/wireguard'},
        ],
        [
            {label: 'API Docs', href: '/docs'},
            {label: 'ReDoc', href: '/redoc'},
            {label: 'Info', href: '/info'},
        ],
    ];

    const params = new URLSearchParams(window.location.search);
    const password = params.get('api_password');
    const suffix = password ? '?api_password=' + encodeURIComponent(password) : '';
    const path = window.location.pathname.replace(/\/+$/, '') || '/';

    const style = document.createElement('style');
    style.textContent = [
        '.ep-nav{position:fixed;top:0;left:0;right:0;z-index:100;',
        'background:rgba(9,9,15,.82);backdrop-filter:blur(20px);',
        'border-bottom:1px solid rgba(255,255,255,.08)}',
        '.ep-nav-inner{max-width:1100px;margin:0 auto;display:flex;gap:6px;',
        'align-items:center;justify-content:center;',
        'padding:9px 1.5rem;overflow-x:auto;scrollbar-width:none}',
        '.ep-nav-inner::-webkit-scrollbar{display:none}',
        '.ep-nav-link{flex:none;padding:7px 12px;border-radius:50px;text-decoration:none;',
        "font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;",
        'font-size:.82rem;font-weight:500;color:#a1a1aa;border:1px solid transparent;',
        'transition:color .2s,background .2s,border-color .2s;white-space:nowrap}',
        '.ep-nav-link:hover{color:#fff;background:rgba(255,255,255,.06)}',
        '.ep-nav-link:focus-visible{outline:2px solid #6366f1;outline-offset:2px}',
        '.ep-nav-link.active{color:#fff;background:rgba(99,102,241,.18);border-color:rgba(99,102,241,.5)}',
        '.ep-nav-sep{flex:none;width:1px;height:18px;background:rgba(255,255,255,.12);margin:0 4px}',
        'body.ep-nav-padded{padding-top:56px}',
        '@media(max-width:900px){.ep-nav-inner{justify-content:flex-start;padding:8px 1rem}',
        'body.ep-nav-padded{padding-top:52px}}',
    ].join('');

    const nav = document.createElement('nav');
    nav.className = 'ep-nav';
    nav.setAttribute('aria-label', 'Main navigation');
    const inner = document.createElement('div');
    inner.className = 'ep-nav-inner';

    groups.forEach((group, index) => {
        if (index) {
            const separator = document.createElement('span');
            separator.className = 'ep-nav-sep';
            inner.appendChild(separator);
        }
        group.forEach(item => {
            const active = (item.paths || [item.href]).includes(path);
            const link = document.createElement('a');
            link.className = 'ep-nav-link' + (active ? ' active' : '');
            link.href = item.href + suffix;
            link.textContent = item.label;
            if (active) link.setAttribute('aria-current', 'page');
            inner.appendChild(link);
        });
    });

    nav.appendChild(inner);
    document.head.appendChild(style);
    document.body.insertBefore(nav, document.body.firstChild);
    document.body.classList.add('ep-nav-padded');
})();
