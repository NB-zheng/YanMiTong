// 项目管理（默认首页）

const ROLE_LABEL = {
    owner:   '负责人',
    member:  '成员',
    auditor: '审计员',
};

async function renderProjects(root) {
    root.innerHTML = `
        <div class="page-header">
            <div>
                <div class="page-title">项目管理</div>
                <div class="page-subtitle">管理你的科研项目，创建新项目或进入已有项目</div>
            </div>
            <button class="btn btn-primary" id="new-project-btn">+ 创建项目</button>
        </div>

        <div class="page-metrics" id="projects-metrics">
            <div class="metric">
                <span class="metric-num" id="stat-project-count">—</span>
                <span class="metric-label">我的项目</span>
            </div>
            <div class="metric-divider" aria-hidden="true"></div>
            <div class="metric">
                <span class="metric-num" id="stat-file-count">—</span>
                <span class="metric-label">可见文件总数</span>
            </div>
        </div>

        <div id="projects-list">${loadingHtml()}</div>
    `;

    document.getElementById('new-project-btn').addEventListener('click', showCreateProjectModal);

    await loadProjectsAndStats();
}

async function loadProjectsAndStats() {
    const myName = getUsername();
    const listEl = document.getElementById('projects-list');

    let projects;
    try {
        projects = await apiGet('/project');
    } catch (err) {
        listEl.innerHTML = `<div class="card" style="color:var(--color-danger)">${escapeHtml(err.message)}</div>`;
        return;
    }

    document.getElementById('stat-project-count').textContent = projects.length;

    if (!projects.length) {
        document.getElementById('stat-file-count').textContent = 0;
        listEl.innerHTML = emptyState(
            '暂无项目',
            '点击右上角"创建项目"按钮，开始你的第一个项目',
        );
        return;
    }

    const details = await Promise.all(projects.map(async (p) => {
        const [members, files] = await Promise.all([
            apiGet(`/project/${p.project_id}/members`).catch(() => []),
            apiGet(`/file/list?project_id=${p.project_id}`).catch(() => []),
        ]);
        // 后端 list_members 已只返回 active 成员
        const myMembership = members.find(m => m.username === myName);
        return {
            project: p,
            memberCount: members.length,
            fileCount: files.length,
            myRole: myMembership ? myMembership.role : null,
        };
    }));

    const totalFiles = details.reduce((s, d) => s + d.fileCount, 0);
    document.getElementById('stat-file-count').textContent = totalFiles;

    listEl.innerHTML = `
        <div class="grid grid-cols-3" id="projects-grid">
            ${details.map(d => projectCardHtml(d)).join('')}
        </div>
    `;
    listEl.querySelectorAll('.project-card').forEach(el => {
        el.addEventListener('click', () => {
            location.hash = `#/project/${el.dataset.id}`;
        });
    });
}

function projectCardHtml({ project, memberCount, myRole }) {
    const p = project;
    const roleLabel = myRole ? (ROLE_LABEL[myRole] || myRole) : '—';
    return `
        <div class="project-card" data-id="${p.project_id}">
            <div class="project-card-field project-card-name">
                <span class="field-label">项目名称：</span>
                <span class="field-value">${escapeHtml(p.project_name)}</span>
            </div>
            <div class="project-card-field project-card-desc">
                <span class="field-label">项目描述：</span>
                <span class="field-value">${escapeHtml(p.description || '暂无描述')}</span>
            </div>
            <div class="project-card-divider"></div>
            <div class="project-card-field">
                <span class="field-label">成员数量：</span>
                <span class="field-value">${memberCount}</span>
            </div>
            <div class="project-card-field">
                <span class="field-label">我的身份：</span>
                <span class="field-value">${escapeHtml(roleLabel)}</span>
            </div>
            <div class="project-card-field">
                <span class="field-label">创建时间：</span>
                <span class="field-value">${formatTime(p.created_time)}</span>
            </div>
        </div>
    `;
}

async function showCreateProjectModal() {
    const body = `
        <div class="form-group">
            <label class="form-label">项目名称 <span class="text-muted text-sm" id="cc-name-count">0/30</span></label>
            <input class="input" name="project_name" placeholder="例如：基因组学研究 2026" required maxlength="30" id="cc-name-input">
        </div>
        <div class="form-group">
            <label class="form-label">项目描述（可选） <span class="text-muted text-sm" id="cc-desc-count">0/200</span></label>
            <textarea class="textarea" name="description" placeholder="简要描述项目目标和范围" maxlength="200" id="cc-desc-input"></textarea>
        </div>
    `;
    const resultPromise = openModal('创建新项目', body, { okText: '创建' });
    setTimeout(() => {
        bindCharCounter('cc-name-input', 'cc-name-count', 30);
        bindCharCounter('cc-desc-input', 'cc-desc-count', 200);
    }, 0);
    const result = await resultPromise;
    if (!result) return;
    if (!result.project_name || !result.project_name.trim()) {
        toast('项目名称不能为空', 'error');
        return;
    }
    try {
        await apiPost('/project', {
            project_name: result.project_name.trim(),
            description: result.description ? result.description.trim() : null,
        });
        toast('项目已创建', 'success');
        await loadProjectsAndStats();
    } catch (err) {
        toast(err.message || '创建失败', 'error');
    }
}
