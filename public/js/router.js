// 前端 hash 路由

const ROUTES = [
    { path: '#/projects',  render: 'renderProjects' },
    { path: '#/profile',   render: 'renderProfile' },
    { path: '#/about',     render: 'renderAbout' },
];

function getCurrentHash() {
    return location.hash || '#/projects';
}

function updateActiveNav() {
    const hash = getCurrentHash();
    document.querySelectorAll('.sidebar-nav a').forEach(a => {
        const href = a.getAttribute('href');
        // 项目详情时高亮"项目管理"
        const isActive = href === hash || (hash.startsWith('#/project/') && href === '#/projects');
        a.classList.toggle('active', isActive);
    });
}

async function route() {
    const hash = getCurrentHash();
    const root = document.getElementById('main-content');
    if (!root) return;
    updateActiveNav();

    root.innerHTML = loadingHtml();

    try {
        if (hash.startsWith('#/project/')) {
            const id = parseInt(hash.split('/')[2]);
            await renderProjectDetail(root, id);
            return;
        }
        for (const r of ROUTES) {
            if (hash === r.path) {
                await window[r.render](root);
                return;
            }
        }
        // 默认
        await renderProjects(root);
    } catch (err) {
        root.innerHTML = `<div class="card"><p style="color:var(--color-danger)">页面加载失败：${escapeHtml(err.message)}</p></div>`;
    }
}

window.addEventListener('hashchange', route);
window.addEventListener('DOMContentLoaded', () => {
    if (!location.hash) location.hash = '#/projects';
    route();
});
