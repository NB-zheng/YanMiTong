// 项目详情：文件 / 成员 / 授权 / 审计 / 告警
//
// 角色权限矩阵（与后端 service 层断言保持一致）：
// - owner   : 拥有项目一切权利（含审计 / 告警 / 取证）
// - member  : 只能下载被授权的文件，不能上传 / 授权 / 删文件 / 管理成员
// - auditor : 只能查看审计 / 告警 / 取证 + 下载被授权的文件
//
// 角色来源：项目详情接口的 viewer_role 字段（与 _currentMembers 二次校验冗余）。

const PROJECT_TABS = [
    { key: 'files',     label: '文件管理' },
    { key: 'members',   label: '成员管理' },
    { key: 'authz',     label: '文件授权' },
    { key: 'alerts',    label: '异常告警' },
    { key: 'audit',     label: '审计日志' },
    { key: 'forensics', label: '泄露取证' },
];

// 注：ROLE_LABEL（owner/member/auditor 中文标签）已在 projects.js 顶层声明并复用，
// 这里不要重复声明（会触发 SyntaxError）。select option 里需要的中文标签直接在
// 局部用 ROLE_LABEL_OPT 变量，不污染顶层作用域。

let _currentProject = null;
let _currentMembers = [];
let _currentTab = 'files';

async function renderProjectDetail(root, projectId) {
    try {
        _currentProject = await apiGet(`/project/${projectId}`);
        _currentMembers = await apiGet(`/project/${projectId}/members`);
    } catch (err) {
        root.innerHTML = `<div class="card" style="color:var(--color-danger)">${escapeHtml(err.message)}</div>`;
        return;
    }

    const role = _currentProject.viewer_role;
    const isOwner = role === 'owner';
    const isMember = role === 'member' || role === 'auditor' || role === 'owner';

    // 非成员（被移除 / 退出项目后还在该 URL）：给一个清晰提示
    if (!isMember) {
        root.innerHTML = `
            <div class="project-detail-header">
                <button class="back-link" onclick="location.hash='#/projects'">← 返回项目列表</button>
                <div class="page-header">
                    <div style="min-width:0; flex:1">
                        <div class="page-title">${escapeHtml(_currentProject.project_name)}</div>
                        <div class="page-subtitle text-muted">您已不在该项目中，仅可查看只读信息。</div>
                    </div>
                </div>
            </div>
            <div class="card">
                ${emptyState('无权操作', '您不是该项目的成员，所有操作按钮均已禁用')}
            </div>
        `;
        return;
    }

    // 顶部操作按钮：
    // - owner : 编辑 + 删除
    // - 其它 : 退出（owner 不可退出自己创建的项目 —— 后端会 400，这里也不显示）
    const actionButtons = isOwner ? `
        <div class="flex gap-2">
            <button class="btn btn-secondary btn-sm" id="edit-project-btn">编辑项目</button>
            <button class="btn btn-secondary btn-sm" id="delete-project-btn" style="color:var(--color-danger); border-color:var(--color-danger)">删除项目</button>
        </div>` : `
        <div class="flex gap-2">
            <button class="btn btn-secondary btn-sm" id="leave-project-btn" style="color:var(--color-danger); border-color:var(--color-danger)">退出项目</button>
        </div>`;

    root.innerHTML = `
        <div class="project-detail-header">
            <button class="back-link" onclick="location.hash='#/projects'">← 返回项目列表</button>
            <div class="page-header">
                <div style="min-width:0; flex:1">
                    <div class="page-title" title="${escapeHtml(_currentProject.project_name)}">${escapeHtml(_currentProject.project_name)}</div>
                    <div class="page-subtitle project-desc-clamp" title="${escapeHtml(_currentProject.description || '暂无描述')}">${escapeHtml(_currentProject.description || '暂无描述')}</div>
                    <div class="page-subtitle text-muted" style="margin-top:2px">创建于 ${formatTime(_currentProject.created_time)}</div>
                </div>
                ${actionButtons}
            </div>
        </div>

        <div class="tabs" id="project-tabs">
            ${PROJECT_TABS.map(t => `<button class="tab" data-tab="${t.key}">${t.label}</button>`).join('')}
        </div>

        <div id="tab-content">${loadingHtml()}</div>
    `;

    document.querySelectorAll('#project-tabs .tab').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    if (isOwner) {
        document.getElementById('edit-project-btn').addEventListener('click', showEditProjectModal);
        document.getElementById('delete-project-btn').addEventListener('click', showDeleteProjectModal);
    } else {
        document.getElementById('leave-project-btn').addEventListener('click', showLeaveProjectModal);
    }

    switchTab(_currentTab in {files:1,members:1,authz:1,audit:1,alerts:1,forensics:1} ? _currentTab : 'files');
}

async function showEditProjectModal() {
    const p = _currentProject;
    const body = `
        <div class="form-group">
            <label class="form-label">项目名称 <span class="text-muted text-sm" id="ep-name-count">0/30</span></label>
            <input class="input" type="text" name="project_name" required minlength="1" maxlength="30" value="${escapeHtml(p.project_name)}" id="ep-name-input">
        </div>
        <div class="form-group">
            <label class="form-label">项目描述 <span class="text-muted text-sm" id="ep-desc-count">0/200</span></label>
            <textarea class="textarea" name="description" placeholder="留空表示清空" maxlength="200" id="ep-desc-input">${escapeHtml(p.description || '')}</textarea>
        </div>
    `;
    const resultPromise = openModal('编辑项目', body, { okText: '保存' });
    setTimeout(() => {
        bindCharCounter('ep-name-input', 'ep-name-count', 30);
        bindCharCounter('ep-desc-input', 'ep-desc-count', 200);
    }, 0);
    const r = await resultPromise;
    if (!r) return;
    const name = (r.project_name || '').trim();
    const desc = (r.description || '').trim();
    if (!name) {
        toast('项目名称不能为空', 'error');
        return;
    }
    try {
        await api(`/project/${p.project_id}`, {
            method: 'PUT',
            body: JSON.stringify({ project_name: name, description: desc || null }),
        });
        toast('项目信息已更新', 'success');
        renderProjectDetail(document.getElementById('main-content'), p.project_id);
    } catch (err) {
        toast(err.message || '修改失败', 'error');
    }
}

async function showDeleteProjectModal() {
    const p = _currentProject;
    // 预先统计将被级联删除的数据，给用户明确预期
    let stats = { files: 0, auths: 0, members: 0, alerts: 0 };
    try {
        const [files, members] = await Promise.all([
            apiGet(`/file/list?project_id=${p.project_id}`).catch(() => []),
            apiGet(`/project/${p.project_id}/members`).catch(() => []),
        ]);
        stats.files = files.length;
        stats.members = members.length;
        // 授权与告警数无法直接查（无对应接口），用 "≥0" 提示
    } catch (_) {}

    const body = `
        <div style="border-left: 3px solid var(--color-danger); background: var(--color-danger-light); padding: 12px 14px; border-radius: var(--radius-md); margin-bottom: var(--space-4);">
            <div style="font-weight:600; color:var(--color-danger); margin-bottom:6px">⚠️ 不可逆操作</div>
            <div class="text-sm">删除项目「<strong>${escapeHtml(p.project_name)}</strong>」将永久清理：</div>
            <ul style="font-size:var(--text-sm); color:var(--text-secondary); margin: 8px 0 0 20px; line-height:1.7">
                <li><strong>${stats.files}</strong> 个文件（含加密密文）</li>
                <li>该项目所有<strong>授权记录</strong></li>
                <li><strong>${stats.members}</strong> 个成员关系</li>
                <li>该项目所有<strong>告警记录</strong></li>
            </ul>
            <div class="text-sm mt-2" style="color:var(--text-secondary)">
                <strong>审计日志</strong>和<strong>水印追溯记录</strong>将保留，用于事后追责和取证。
            </div>
        </div>
        <div class="form-group">
            <label class="form-label">为确认删除，请输入项目完整名称：<strong style="font-family:var(--font-mono); color:var(--color-danger)">${escapeHtml(p.project_name)}</strong></label>
            <input class="input" type="text" name="confirm_name" id="del-confirm-input" placeholder="${escapeHtml(p.project_name)}" autocomplete="off">
        </div>
    `;
    // 自定义按钮文字与样式
    const r = await openModal('删除项目', body, {
        okText: '我已知晓，永久删除',
        dangerous: true,
        cancelText: '取消',
    });
    if (!r) return;
    if ((r.confirm_name || '').trim() !== p.project_name) {
        toast('项目名称不匹配，已取消删除', 'warning');
        return;
    }
    try {
        const resp = await api(`/project/${p.project_id}`, { method: 'DELETE' }).then(r => r.json());
        toast(resp.message || '项目已删除', 'success');
        setTimeout(() => { location.hash = '#/projects'; }, 600);
    } catch (err) {
        toast(err.message || '删除失败', 'error');
    }
}

async function showLeaveProjectModal() {
    const p = _currentProject;
    const body = `
        <div style="border-left: 3px solid var(--color-warning); background: var(--color-warning-light); padding: 12px 14px; border-radius: var(--radius-md); margin-bottom: var(--space-4);">
            <div style="font-weight:600; color:var(--color-warning); margin-bottom:6px">退出确认</div>
            <div class="text-sm">退出项目「<strong>${escapeHtml(p.project_name)}</strong>」后：</div>
            <ul style="font-size:var(--text-sm); color:var(--text-secondary); margin: 8px 0 0 20px; line-height:1.7">
                <li>项目将从你的「项目管理」列表中消失</li>
                <li>你<strong>已获得的文件授权不会自动失效</strong></li>
                <li>你上传过的文件依然保留在项目里</li>
                <li>如果想重新加入，需要项目负责人再次添加你</li>
            </ul>
        </div>
    `;
    const ok = await openModal('退出项目', body, {
        okText: '确认退出',
        dangerous: true,
    });
    if (!ok) return;
    try {
        const resp = await apiPost(`/project/${p.project_id}/leave`, {});
        toast(resp.message || '已退出', 'success');
        setTimeout(() => { location.hash = '#/projects'; }, 600);
    } catch (err) {
        toast(err.message || '退出失败', 'error');
    }
}

function switchTab(key) {
    _currentTab = key;
    document.querySelectorAll('#project-tabs .tab').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === key);
    });
    const c = document.getElementById('tab-content');
    c.innerHTML = loadingHtml();
    const pid = _currentProject.project_id;
    if (key === 'files')     return renderFilesTab(c, pid);
    if (key === 'members')   return renderMembersTab(c, pid);
    if (key === 'authz')     return renderAuthzTab(c, pid);
    if (key === 'audit')     return renderAuditTab(c, pid);
    if (key === 'alerts')    return renderAlertsTab(c, pid);
    if (key === 'forensics') return renderForensicsTab(c, pid);
}

// ===== 角色 helpers（全部基于 viewer_role 字段） =====
function viewerRole() {
    return _currentProject ? _currentProject.viewer_role : null;
}
function isOwner()    { return viewerRole() === 'owner'; }
function isAuditor()  { return viewerRole() === 'auditor'; }
function isMember()   { return viewerRole() === 'member'; }
function canAudit()   { return isOwner() || isAuditor(); }
// 兼容旧调用（少数位置仍可能用到）
function getMyRole()   { return viewerRole(); }

// ========== Tab 1：文件管理 ==========
// 带状态反馈的下载包装函数
async function downloadFileWithFeedback(fileId) {
    const btn = document.getElementById(`download-btn-${fileId}`);
    if (!btn) return;
    const originalText = btn.textContent;
    btn.disabled = true;

    try {
        await downloadFileById(fileId, (p) => {
            if (p.phase === 'decrypt') {
                btn.textContent = '解密中…';
            } else if (p.phase === 'download') {
                btn.textContent = `下载中 ${p.percent}%`;
            }
        });
    } catch (err) {
        toast(err.message || '下载失败', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function renderFilesTab(c, pid) {
    try {
        const [files, receivedAuths] = await Promise.all([
            apiGet(`/file/list?project_id=${pid}`),
            apiGet('/authz/granted-to-me').catch(() => []),
        ]);
        const myName = getUsername();
        // 当前用户可访问的 file_id 集合：我作为 owner 自有全部 + 别人有效授权给我的
        // 非 owner 需要按授权表判断可见性；owner 直接可见全部项目文件。
        const accessibleIds = new Set();
        if (isOwner()) {
            for (const f of files) accessibleIds.add(f.file_id);
        } else {
            for (const a of receivedAuths) {
                if (a.status === 'valid') accessibleIds.add(a.file_id);
            }
        }

        // 顶部按钮：仅 owner 显示"上传文件"
        const headerHtml = `
            <div class="flex-between mb-4">
                <div class="text-secondary">共 ${files.length} 个文件</div>
                ${isOwner() ? `<button class="btn btn-primary" id="upload-btn">+ 上传文件</button>
                <input type="file" id="file-input" style="display:none">` : ''}
            </div>`;

        c.innerHTML = `
            ${headerHtml}
            ${files.length ? `
                <div class="table-wrap">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>文件名</th>
                                <th>类型</th>
                                <th>大小</th>
                                <th>上传者</th>
                                <th>上传时间</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${files.map(f => {
                                const isMine = f.uploader_username === myName;
                                const canAccess = isOwner() || isMine || accessibleIds.has(f.file_id);
                                // 仅有授权访问权且是 owner，才能发起 grant（按产品矩阵）
                                const canGrant = isOwner() && canAccess;
                                // 删除文件：仅 owner
                                const canDelete = isOwner();
                                const nameJson = JSON.stringify(f.original_filename).replace(/"/g,'&quot;');
                                return `
                                <tr>
                                    <td><strong>${escapeHtml(f.original_filename)}</strong></td>
                                    <td><span class="badge badge-muted">${escapeHtml(fileTypeLabel(f.file_type))}</span></td>
                                    <td class="text-secondary">${fileSizeStr(f.file_size)}</td>
                                    <td class="text-secondary">${escapeHtml(f.uploader_username)}</td>
                                    <td class="text-secondary">${formatTime(f.created_time)}</td>
                                    <td>
                                        ${canAccess
                                            ? `<button class="btn btn-text btn-sm" id="download-btn-${f.file_id}" onclick="downloadFileWithFeedback(${f.file_id})">下载</button>`
                                            : `<button class="btn btn-text btn-sm btn-disabled" title="无权限：请先获得文件所有者的授权" onclick="toast('无权限下载，请联系项目负责人授权','warning')">下载</button>`}
                                        ${canGrant
                                            ? `<button class="btn btn-text btn-sm" onclick="showGrantModal(${f.file_id}, ${nameJson}, ${JSON.stringify(f.uploader_username).replace(/"/g,'&quot;')})">授权</button>`
                                            : ''}
                                        ${canDelete
                                            ? `<button class="btn btn-text btn-sm" style="color:var(--color-danger)" onclick="deleteFile(${f.file_id}, ${nameJson})">删除</button>`
                                            : ''}
                                    </td>
                                </tr>
                                `;
                            }).join('')}
                        </tbody>
                    </table>
                </div>
            ` : emptyState('暂无文件', isOwner() ? '点击上方"上传文件"按钮添加第一个文件' : '等待项目负责人上传文件')}
        `;

        // 仅 owner 绑定上传控件
        if (isOwner()) {
            const input = document.getElementById('file-input');
            document.getElementById('upload-btn').addEventListener('click', () => input.click());
            input.addEventListener('change', async (e) => {
                const file = e.target.files[0];
                if (!file) return;
                const fd = new FormData();
                fd.append('project_id', String(pid));
                fd.append('file', file);
                const uploadBtn = document.getElementById('upload-btn');
                uploadBtn.disabled = true;
                uploadBtn.textContent = '上传中 0%';
                try {
                    await apiUploadWithProgress('/file/upload', fd, (p) => {
                        if (p.phase === 'upload') {
                            uploadBtn.textContent = `上传中 ${p.percent}%`;
                        } else if (p.phase === 'server') {
                            // 字节已传完，后端在做 SM3 摘要 + SM4 加密 + 入库
                            uploadBtn.textContent = '服务端加密中…';
                        }
                    });
                    toast('文件上传成功', 'success');
                    renderFilesTab(c, pid);
                } catch (err) {
                    toast(err.message || '上传失败', 'error');
                    uploadBtn.disabled = false;
                    uploadBtn.textContent = '+ 上传文件';
                }
            });
        }
    } catch (err) {
        c.innerHTML = `<div class="card" style="color:var(--color-danger)">${escapeHtml(err.message)}</div>`;
    }
}

async function deleteFile(fileId, fileName) {
    if (!isOwner()) {
        toast('仅项目负责人可删除文件', 'error');
        return;
    }
    const ok = await confirmDialog(
        '删除文件',
        `确认删除「${fileName}」？该操作不可撤销，会同时删除文件的所有授权。`,
        { okText: '删除', dangerous: true },
    );
    if (!ok) return;
    try {
        await apiDelete(`/file/${fileId}`);
        toast('文件已删除', 'success');
        renderFilesTab(document.getElementById('tab-content'), _currentProject.project_id);
    } catch (err) {
        toast(err.message || '删除失败', 'error');
    }
}

async function showGrantModal(fileId, fileName, uploaderUsername) {
    if (!isOwner()) {
        toast('仅项目负责人可发起授权', 'error');
        return;
    }
    const myName = getUsername();
    const isTransfer = uploaderUsername !== myName;   // 不是上传者 → 转授
    const verbA = isTransfer ? '转授' : '授权';        // 动词

    // grantee 候选 = 当前项目的成员，排除自己 和 文件上传者
    const pid = _currentProject.project_id;
    let members = [];
    try {
        members = await apiGet(`/project/${pid}/members`);
    } catch (err) {
        toast('加载项目成员失败：' + err.message, 'error');
        return;
    }
    const grantees = members.filter(m => m.username !== myName && m.username !== uploaderUsername);
    if (!grantees.length) {
        toast(`当前项目暂无可${verbA}的其他成员`, 'warning');
        return;
    }

    // 默认有效期：当前时间 + 7 天
    const defaultExpire = new Date(Date.now() + 7 * 86400000);
    const pad = n => String(n).padStart(2, '0');
    const defaultStr = `${defaultExpire.getFullYear()}-${pad(defaultExpire.getMonth()+1)}-${pad(defaultExpire.getDate())} ${pad(defaultExpire.getHours())}:${pad(defaultExpire.getMinutes())}`;

    const hintText = isTransfer
        ? `该文件由 ${uploaderUsername} 上传；你是经过授权获得访问权，可以继续把权限转给项目内其他成员。`
        : '被授权人将获得下载该文件的权限。';

    const body = `
        <div class="form-group">
            <label class="form-label">文件</label>
            <div>${escapeHtml(fileName)}</div>
            <div class="text-sm text-muted mt-2">${escapeHtml(hintText)}</div>
        </div>
        <div class="form-group">
            <label class="form-label">${verbA}给</label>
            <select class="select" name="grantee_username" required>
                ${grantees.map(m => `<option value="${escapeHtml(m.username)}">${escapeHtml(m.username)} · ${escapeHtml(ROLE_LABEL[m.role] || m.role)}</option>`).join('')}
            </select>
        </div>
        <div class="form-group">
            <label class="form-label">有效期至</label>
            <input class="input" type="text" name="expire_at" value="${defaultStr}" id="grant-expire-input" placeholder="点击选择日期与时间">
        </div>
        <div class="form-group">
            <label class="form-label">最大下载次数（留空不限）</label>
            <input class="input" type="number" name="max_downloads" min="1" placeholder="不限">
        </div>
    `;
    const modalTitle = isTransfer ? '转授该文件给项目成员' : '授权文件给项目成员';
    const modalPromise = openModal(modalTitle, body, { okText: verbA });
    const input = document.getElementById('grant-expire-input');
    if (input) bindDatePicker(input, { initial: defaultExpire, min: new Date() });
    const ok = await modalPromise;
    if (!ok) return;

    const expDate = parseDpValue(ok.expire_at);
    if (!expDate) {
        toast('请选择有效期', 'error');
        return;
    }
    const minutes = Math.round((expDate.getTime() - Date.now()) / 60000);
    if (minutes < 1) {
        toast('有效期必须在未来时间', 'error');
        return;
    }

    try {
        await apiPost('/authz/grant', {
            file_id: fileId,
            grantee_username: ok.grantee_username,
            expire_minutes: minutes,
            max_downloads: ok.max_downloads ? parseInt(ok.max_downloads) : null,
        });
        toast(`${verbA}成功`, 'success');
    } catch (err) {
        toast(err.message || `${verbA}失败`, 'error');
    }
}

// ========== Tab 2：成员管理 ==========
// 可见性：所有项目成员都能看到成员列表。
// 操作：只有项目负责人 (owner) 能"添加成员 / 改角色 / 移除"。
async function renderMembersTab(c, pid) {
    try {
        _currentMembers = await apiGet(`/project/${pid}/members`);
        const ownerView = isOwner();
        c.innerHTML = `
            <div class="flex-between mb-4">
                <div class="text-secondary">共 ${_currentMembers.length} 名成员</div>
                ${ownerView ? `<button class="btn btn-primary" id="add-member-btn">+ 添加成员</button>` : ''}
            </div>
            <div class="table-wrap">
                <table class="table">
                    <thead>
                        <tr>
                            <th>用户名</th>
                            <th>角色</th>
                            <th>加入时间</th>
                            <th>操作</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${_currentMembers.map(m => {
                            const isOwnerRow = m.role === 'owner';
                        
                            // 其余成员由 owner 看到「改角色 / 移除」按钮，非 owner 看到「-」。
                            const actionCell = isOwnerRow
                                ? '<span class="text-muted text-sm">-</span>'
                                : (ownerView
                                    ? `<button class="btn btn-text btn-sm" onclick="changeMemberRole(${pid}, ${JSON.stringify(m.username).replace(/"/g,'&quot;')}, ${JSON.stringify(m.role).replace(/"/g,'&quot;')})">改角色</button>
                                       <button class="btn btn-text btn-sm" style="color:var(--color-danger)" onclick="removeMember(${pid}, ${JSON.stringify(m.username).replace(/"/g,'&quot;')})">移除</button>`
                                    : '<span class="text-muted text-sm">-</span>');
                            return `
                            <tr>
                                <td><strong>${escapeHtml(m.username)}</strong></td>
                                <td>${roleBadge(m.role)}</td>
                                <td class="text-secondary">${formatTime(m.joined_time)}</td>
                                <td>${actionCell}</td>
                            </tr>`;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        `;
        if (ownerView) {
            document.getElementById('add-member-btn').addEventListener('click', () => showAddMemberModal(pid));
        }
    } catch (err) {
        c.innerHTML = `<div class="card" style="color:var(--color-danger)">${escapeHtml(err.message)}</div>`;
    }
}

async function showAddMemberModal(pid) {
    const body = `
        <div class="form-group">
            <label class="form-label">用户名</label>
            <input class="input" type="text" name="username" placeholder="输入要添加的用户名" required autocomplete="off">
        </div>
        <div class="form-group">
            <label class="form-label">角色</label>
            <select class="select" name="role">
                <option value="member">成员（member）</option>
                <option value="auditor">审计员（auditor）</option>
            </select>
            <div class="text-sm text-muted mt-2">负责人 (owner) 由创建者担任，不通过此接口指定。</div>
        </div>
    `;
    const r = await openModal('添加成员', body, { okText: '添加' });
    if (!r) return;
    const username = (r.username || '').trim();
    if (!username) {
        toast('请输入用户名', 'error');
        return;
    }
    // 前端先校验是否已是成员，避免无谓请求
    if (_currentMembers.some(m => m.username === username)) {
        toast(`「${username}」已经是项目成员`, 'warning');
        return;
    }
    try {
        await apiPost(`/project/${pid}/members`, {
            username,
            role: r.role,
        });
        toast('成员已添加', 'success');
        renderMembersTab(document.getElementById('tab-content'), pid);
    } catch (err) {
        // 后端 404 → 用户不存在
        if (/不存在|404/.test(err.message)) {
            toast(`用户「${username}」不存在`, 'error');
        } else {
            toast(err.message || '添加失败', 'error');
        }
    }
}

async function changeMemberRole(pid, username, currentRole) {
    if (!isOwner()) {
        toast('仅项目负责人可修改成员角色', 'error');
        return;
    }
    const roles = [
        ['member',  '成员'],
        ['auditor', '审计员'],
    ];
    const body = `
        <div class="form-group">
            <label class="form-label">用户</label>
            <div>${escapeHtml(username)}</div>
        </div>
        <div class="form-group">
            <label class="form-label">新角色</label>
            <select class="select" name="role">
                ${roles.map(([k, label]) => `<option value="${k}" ${k===currentRole?'selected':''}>${label}（${k}）</option>`).join('')}
            </select>
        </div>
    `;
    const r = await openModal('修改成员角色', body, { okText: '保存' });
    if (!r) return;
    if (r.role === currentRole) return;
    try {
        // 复用 add_member：当 (project_id, user_id) 已存在时后端会更新 role
        await apiPost(`/project/${pid}/members`, {
            username,
            role: r.role,
        });
        toast('角色已更新', 'success');
        renderMembersTab(document.getElementById('tab-content'), pid);
    } catch (err) {
        toast(err.message || '修改失败', 'error');
    }
}

async function removeMember(pid, username) {
    if (!isOwner()) {
        toast('仅项目负责人可移除成员', 'error');
        return;
    }
    if (!await confirmDialog('移除成员', `确认要移除用户 ${username} 吗？`, { okText: '移除' })) return;
    try {
        await apiDelete(`/project/${pid}/members/${encodeURIComponent(username)}`);
        toast('成员已移除', 'success');
        renderMembersTab(document.getElementById('tab-content'), pid);
    } catch (err) {
        toast(err.message || '移除失败', 'error');
    }
}

// ========== Tab 3：文件授权 ==========
async function renderAuthzTab(c, pid) {
    try {
        const myName = getUsername();
        // owner 同时看两块；member / auditor 只看"我收到的"
        const apiCalls = isOwner()
            ? [
                apiGet('/authz/granted-by-me'),
                apiGet('/authz/granted-to-me'),
                apiGet(`/file/list?project_id=${pid}`),
              ]
            : [
                Promise.resolve([]),                                // granted 占位：member/auditor 不显示
                apiGet('/authz/granted-to-me'),
                apiGet(`/file/list?project_id=${pid}`),
              ];
        const [granted, received, files] = await Promise.all(apiCalls);
        const fileIds = new Set(files.map(f => f.file_id));
        const fileNameMap = Object.fromEntries(files.map(f => [f.file_id, f.original_filename]));
        const receivedHere = received.filter(a => fileIds.has(a.file_id));

        if (isOwner()) {
            // 负责人视角：只显示"我授出的"。
            // 负责人自己不接收任何授权（grant 接口禁止 grantee==grantor），
            // "我收到的" 在此场景下恒为空，没有展示价值，因此整块不渲染。
            const grantedHere = granted.filter(a => fileIds.has(a.file_id));
            c.innerHTML = `
                <div class="card">
                    <div class="card-title">我授出的（${grantedHere.length}）</div>
                    ${grantedHere.length ? authzTable(grantedHere, fileNameMap, true) : emptyState('暂无授权', '在"文件管理"中选择文件进行授权')}
                </div>
            `;
        } else {
            // member / auditor 视角：只显示"授权给我"
            c.innerHTML = `
                <div class="card">
                    <div class="card-title">${escapeHtml(myName)} 收到的授权（${receivedHere.length}）</div>
                    ${receivedHere.length ? authzTable(receivedHere, fileNameMap, false) : emptyState('暂无收到的授权', '请项目负责人在"文件管理"中分配')}
                </div>
            `;
        }
    } catch (err) {
        c.innerHTML = `<div class="card" style="color:var(--color-danger)">${escapeHtml(err.message)}</div>`;
    }
}

function authzTable(list, fileNameMap, iAmGrantor) {
    return `
        <div class="table-wrap" style="border:none">
            <table class="table">
                <thead>
                    <tr>
                        <th>文件</th>
                        <th>${iAmGrantor ? '被授权用户' : '授权人'}</th>
                        <th>过期时间</th>
                        <th>下载次数</th>
                        <th>状态</th>
                        ${iAmGrantor ? '<th>操作</th>' : ''}
                    </tr>
                </thead>
                <tbody>
                    ${list.map(a => `
                        <tr>
                            <td><strong>${escapeHtml(fileNameMap[a.file_id] || ('已删除文件 #' + a.file_id))}</strong></td>
                            <td>${escapeHtml(iAmGrantor ? a.grantee_username : a.grantor_username)}</td>
                            <td class="text-secondary">${formatTime(a.expire_time)}</td>
                            <td class="text-secondary">${a.used_downloads}${a.max_downloads ? ' / ' + a.max_downloads : ''}</td>
                            <td>${statusBadge(a.status)}</td>
                            ${iAmGrantor ? `<td>
                                ${a.status === 'valid'
                                    ? `<button class="btn btn-text btn-sm" style="color:var(--color-danger)" id="revoke-btn-${a.auth_id}" onclick="revokeAuth(${a.auth_id})">撤销</button>`
                                    : (a.revoke_mode === 'weak'
                                        ? `<button class="btn btn-text btn-sm" onclick="restoreAuth(${a.auth_id})">恢复</button>`
                                        : '<span class="text-muted text-sm">已强撤销</span>')}
                            </td>` : ''}
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

async function revokeAuth(authId) {
    if (!isOwner()) {
        toast('仅项目负责人可撤销授权', 'error');
        return;
    }
    // 模态框：让负责人选择弱撤销或强撤销
    const body = `
        <div class="form-group">
            <label class="form-label">撤销方式</label>
            <div style="display:flex; flex-direction:column; gap:10px; margin-top:4px">
                <label style="display:flex; align-items:flex-start; gap:8px; cursor:pointer">
                    <input type="radio" name="revoke_mode" value="weak" checked style="margin-top:2px">
                    <span>
                        <strong>弱撤销</strong><br>
                        <span class="text-sm text-secondary">仅标记撤销，不重加密文件，执行快，支持后续恢复。适合临时协作到期。</span>
                    </span>
                </label>
                <label style="display:flex; align-items:flex-start; gap:8px; cursor:pointer">
                    <input type="radio" name="revoke_mode" value="strong" style="margin-top:2px">
                    <span>
                        <strong>强撤销</strong><br>
                        <span class="text-sm text-secondary">重新生成文件密钥并重加密所有副本，密钥层彻底隔离，不可恢复。适合密钥泄露等高安全场景。</span>
                    </span>
                </label>
            </div>
        </div>
    `;
    const r = await openModal('撤销授权', body, { okText: '确认撤销', dangerous: true });
    if (!r) return;
    const mode = r.revoke_mode || 'weak';
    const confirmMsg = mode === 'strong'
        ? '强撤销将重新生成文件密钥并重加密，确认继续？此操作不可恢复。'
        : '确认对指定用户撤销授权？撤销后可在「操作」列恢复。';
    if (!await confirmDialog('确认撤销', confirmMsg, { okText: '确认撤销', dangerous: true })) return;

    // 显示状态反馈
    const btn = document.getElementById(`revoke-btn-${authId}`);
    const originalText = btn ? btn.textContent : '撤销';
    if (btn) {
        btn.disabled = true;
        btn.textContent = mode === 'strong' ? '重加密中…' : '撤销中…';
    }

    try {
        await apiPost('/authz/revoke', { auth_id: authId, mode });
        toast(mode === 'strong' ? '强撤销完成（文件已重加密）' : '弱撤销完成', 'success');
        renderAuthzTab(document.getElementById('tab-content'), _currentProject.project_id);
    } catch (err) {
        toast(err.message || '撤销失败', 'error');
        // 恢复按钮状态
        if (btn) {
            btn.disabled = false;
            btn.textContent = originalText;
        }
    }
}

async function restoreAuth(authId) {
    if (!isOwner()) {
        toast('仅项目负责人可恢复授权', 'error');
        return;
    }
    if (!await confirmDialog('恢复授权', '恢复后用户可重新下载文件，确认继续？', { okText: '恢复' })) return;
    try {
        await apiPost('/authz/restore', { auth_id: authId });
        toast('授权已恢复', 'success');
        renderAuthzTab(document.getElementById('tab-content'), _currentProject.project_id);
    } catch (err) {
        toast(err.message || '恢复失败', 'error');
    }
}

// 操作类型 → 中文
const OPERATION_LABEL = {
    create_project: '创建项目',
    update_project: '修改项目',
    delete_project: '删除项目',
    add_member:     '添加成员',
    remove_member:  '移除成员',
    upload:         '上传文件',
    download:       '下载文件',
    delete_file:    '删除文件',
    grant:          '文件授权',
    revoke:         '撤销授权',
    restore_auth:    '恢复授权',
    forensics:      '取证分析',
};
// 对象类型 → 中文
const OBJECT_TYPE_LABEL = {
    file:    '文件',
    project: '项目',
    member:  '成员',
    auth:    '授权',
};

function operationLabel(op) {
    return OPERATION_LABEL[op] || op;
}
function objectTypeLabel(t) {
    return OBJECT_TYPE_LABEL[t] || (t || '-');
}

// ========== Tab 4：审计日志（owner + auditor） ==========
const AUDIT_PAGE_SIZE = 50;
let _auditLoadedLogs = [];   // 累积所有已加载的日志
let _auditOldestId = null;   // 最早 log_id（游标）
let _auditHasMore = true;

async function renderAuditTab(c, pid) {
    if (!canAudit()) {
        c.innerHTML = `<div class="card">${emptyState('无权访问', '审计日志仅限项目负责人或审计员查看')}</div>`;
        return;
    }

    // 重置分页状态
    _auditLoadedLogs = [];
    _auditOldestId = null;
    _auditHasMore = true;

    // 骨架
    c.innerHTML = `
        <div class="audit-chain-bar" id="audit-chain-bar">
            <span class="dp-time-label" style="margin-right:8px">哈希链完整性</span>
            <span id="audit-verify-badge" class="text-secondary text-sm">校验中…</span>
            <div style="flex:1"></div>
            <span class="text-secondary text-sm" id="audit-total"></span>
            <button class="btn btn-text btn-sm" id="audit-recheck-btn" title="重新校验">↻ 重新校验</button>
        </div>
        <div class="table-wrap" id="audit-table-wrap">
            <table class="table">
                <thead>
                    <tr>
                        <th>操作</th>
                        <th>操作者</th>
                        <th>对象类型</th>
                        <th>对象</th>
                        <th>结果</th>
                        <th>时间</th>
                    </tr>
                </thead>
                <tbody id="audit-tbody"></tbody>
            </table>
            <div class="audit-loadmore" id="audit-loadmore-wrap" style="display:none">
                <button class="btn btn-secondary btn-sm" id="audit-loadmore-btn">加载更早的日志</button>
            </div>
        </div>
    `;

    document.getElementById('audit-recheck-btn').addEventListener('click', () => loadVerifyStatus(pid));
    document.getElementById('audit-loadmore-btn').addEventListener('click', () => loadMoreLogs(pid));

    await Promise.all([loadVerifyStatus(pid), loadMoreLogs(pid)]);
}

async function loadVerifyStatus(pid) {
    const badgeEl = document.getElementById('audit-verify-badge');
    const totalEl = document.getElementById('audit-total');
    const barEl = document.getElementById('audit-chain-bar');
    if (!badgeEl) return;
    badgeEl.innerHTML = `<span class="text-secondary text-sm">校验中…</span>`;
    try {
        const r = await apiGet(`/audit/verify?project_id=${pid}`);
        if (r.ok) {
            badgeEl.innerHTML = `<span class="audit-verify-dot ok"></span><span style="color:var(--color-success); font-weight:500">完整</span>`;
            barEl.classList.remove('broken');
        } else {
            badgeEl.innerHTML = `<span class="audit-verify-dot bad"></span><span style="color:var(--color-danger); font-weight:500">链断裂 @ #${r.broken_at_log_id}</span>`;
            barEl.classList.add('broken');
        }
        totalEl.textContent = `共 ${r.total} 条日志`;
    } catch (err) {
        badgeEl.innerHTML = `<span style="color:var(--color-danger)">校验失败：${escapeHtml(err.message)}</span>`;
    }
}

async function loadMoreLogs(pid) {
    const btn = document.getElementById('audit-loadmore-btn');
    const wrap = document.getElementById('audit-loadmore-wrap');
    const tbody = document.getElementById('audit-tbody');
    if (!tbody) return;
    if (btn) {
        btn.disabled = true;
        btn.textContent = '加载中…';
    }
    try {
        const url = _auditOldestId
            ? `/audit/logs?project_id=${pid}&limit=${AUDIT_PAGE_SIZE}&before_log_id=${_auditOldestId}`
            : `/audit/logs?project_id=${pid}&limit=${AUDIT_PAGE_SIZE}`;
        const rows = await apiGet(url);
        _auditLoadedLogs.push(...rows);
        if (rows.length) {
            _auditOldestId = rows[rows.length - 1].log_id;
        }
        _auditHasMore = rows.length === AUDIT_PAGE_SIZE;

        // 首次加载且空
        if (!_auditLoadedLogs.length) {
            tbody.parentElement.parentElement.innerHTML =
                emptyState('暂无审计日志', '当前项目还没有任何被记录的操作');
            return;
        }

        // append rows
        tbody.innerHTML = _auditLoadedLogs.map(l => `
            <tr>
                <td><strong>${escapeHtml(operationLabel(l.operation))}</strong></td>
                <td>${escapeHtml(l.username)}</td>
                <td class="text-secondary">${escapeHtml(objectTypeLabel(l.object_type))}</td>
                <td class="text-secondary">${escapeHtml(l.object_label || '-')}</td>
                <td>${statusBadge(l.result)}</td>
                <td class="text-secondary">${formatTime(l.timestamp)}</td>
            </tr>
        `).join('');

        wrap.style.display = _auditHasMore ? 'flex' : 'none';
        if (btn) {
            btn.disabled = false;
            btn.textContent = '加载更早的日志';
        }
    } catch (err) {
        if (btn) {
            btn.disabled = false;
            btn.textContent = '加载失败，点击重试';
        }
        toast(err.message || '加载失败', 'error');
    }
}

// 告警类型 → 中文
const ALERT_TYPE_LABEL = {
    access_after_revoke: '撤销后访问',
    high_freq_download:  '高频下载',
    verify_fail:         '完整性校验失败',
    abnormal_ip:         '异常 IP',
};
function alertTypeLabel(t) {
    return ALERT_TYPE_LABEL[t] || t;
}

// ========== Tab：异常告警（owner + auditor） ==========
async function renderAlertsTab(c, pid) {
    if (!canAudit()) {
        c.innerHTML = `<div class="card">${emptyState('无权访问', '异常告警仅限项目负责人或审计员查看')}</div>`;
        return;
    }
    try {
        const alerts = await apiGet(`/audit/alerts?project_id=${pid}`);
        const unhandled = alerts.filter(a => !a.handled).length;
        c.innerHTML = `
            <div class="flex-between mb-4">
                <div class="text-secondary">共 ${alerts.length} 条告警，<strong style="color:var(--color-danger)">${unhandled}</strong> 条待处理</div>
            </div>
            ${alerts.length ? `
                <div class="table-wrap">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>类型</th>
                                <th>严重程度</th>
                                <th>关联用户</th>
                                <th>消息</th>
                                <th>时间</th>
                                <th>状态</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${alerts.map(a => `
                                <tr style="${a.handled ? 'opacity:0.55' : ''}">
                                    <td><strong>${escapeHtml(alertTypeLabel(a.alert_type))}</strong></td>
                                    <td>${severityBadge(a.severity)}</td>
                                    <td class="text-secondary">${escapeHtml(a.username || '-')}</td>
                                    <td class="text-secondary">${escapeHtml(a.message || '-')}</td>
                                    <td class="text-secondary">${formatTime(a.created_time)}</td>
                                    <td>${a.handled ? '<span class="badge badge-muted">已处理</span>' : '<span class="badge badge-warning">待处理</span>'}</td>
                                    <td>
                                        ${!a.handled
                                            ? `<button class="btn btn-text btn-sm" onclick="handleAlert(${a.alert_id})">标记已处理</button>`
                                            : ''}
                                        <button class="btn btn-text btn-sm" style="color:var(--color-danger)" onclick="deleteAlert(${a.alert_id})">删除</button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            ` : emptyState('暂无告警', '项目运行良好')}
        `;
    } catch (err) {
        c.innerHTML = `<div class="card" style="color:var(--color-danger)">${escapeHtml(err.message)}</div>`;
    }
}

function severityBadge(s) {
    const map = {
        high:   ['高', 'badge-danger'],
        medium: ['中', 'badge-warning'],
        low:    ['低', 'badge-info'],
    };
    const [label, cls] = map[s] || [s, 'badge-muted'];
    return `<span class="badge ${cls}">${label}</span>`;
}

async function handleAlert(alertId) {
    if (!canAudit()) {
        toast('无权处理告警', 'error');
        return;
    }
    try {
        await apiPost(`/audit/alerts/${alertId}/handle`, {});
        toast('已标记处理', 'success');
        renderAlertsTab(document.getElementById('tab-content'), _currentProject.project_id);
    } catch (err) {
        toast(err.message || '操作失败', 'error');
    }
}

async function deleteAlert(alertId) {
    if (!canAudit()) {
        toast('无权删除告警', 'error');
        return;
    }
    if (!await confirmDialog('删除告警', '确认删除该告警吗？此操作不可恢复。', { okText: '删除' })) return;
    try {
        await apiDelete(`/audit/alerts/${alertId}`);
        toast('告警已删除', 'success');
        renderAlertsTab(document.getElementById('tab-content'), _currentProject.project_id);
    } catch (err) {
        toast(err.message || '删除失败', 'error');
    }
}

// ========== Tab 6：泄露取证（owner + auditor） ==========
async function renderForensicsTab(c, pid) {
    if (!canAudit()) {
        c.innerHTML = `<div class="card">${emptyState('无权访问', '泄露取证仅限项目负责人或审计员执行')}</div>`;
        return;
    }
    c.innerHTML = `
        <div class="card mb-4">
            <div class="card-title">泄露文件追溯</div>
            <p class="text-secondary text-sm" style="margin-bottom:var(--space-4)">
                上传疑似泄露的文件，平台将从其数字水印中提取指纹，定位下载者。
                <strong>只能追溯从本项目下载的文件</strong>，跨项目命中不会披露下载者信息。
            </p>
            <div class="upload-zone" id="forensics-zone">
                <div class="upload-zone-title">📄 拖拽文件到这里 或 点击选择文件</div>
                <div class="upload-zone-hint">支持 PDF / Word / 图片 / 文本等格式</div>
                <input type="file" id="forensics-file-input" style="display:none">
            </div>
        </div>
        <div id="forensics-result"></div>
    `;

    const zone = document.getElementById('forensics-zone');
    const fileInput = document.getElementById('forensics-file-input');

    zone.addEventListener('click', () => fileInput.click());
    zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length) handleProjectForensics(pid, e.dataTransfer.files[0]);
    });
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) handleProjectForensics(pid, e.target.files[0]);
    });
}

async function handleProjectForensics(pid, file) {
    const result = document.getElementById('forensics-result');
    result.innerHTML = `<div class="card">${loadingHtml('正在分析文件指纹…')}</div>`;
    try {
        const fd = new FormData();
        fd.append('file', file);
        const r = await apiUpload(`/project/${pid}/forensics`, fd);

        const matches = r.matches || [];
        const leakerCount = r.leaker_count || 0;
        const crossProjectCount = r.cross_project_count || 0;
        const totalCount = r.total_count || 0;

        // 构建匹配列表 HTML
        let matchesHtml = '';
        if (matches.length > 0) {
            const rows = matches.map((m, i) => `
                <tr>
                    <td class="text-center">${i + 1}</td>
                    <td><strong>${escapeHtml(m.username || '-')}</strong></td>
                    <td>${formatTime(m.download_time)}</td>
                    <td class="text-secondary text-sm">${escapeHtml(m.client_ip || '-')}</td>
                </tr>
            `).join('');

            matchesHtml = `
                <table class="table" style="margin-top:var(--space-3)">
                    <thead>
                        <tr>
                            <th style="width:50px;text-align:center">#</th>
                            <th>下载用户</th>
                            <th>下载时间</th>
                            <th>客户端IP</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            `;
        }

        // 状态徽章和标题
        let statusBadge = '';
        let statusTitle = '';
        if (leakerCount > 0) {
            statusBadge = `<span class="badge badge-danger">已匹配</span>`;
            statusTitle = `追溯到 ${leakerCount} 位泄露者（${matches.length} 条记录）`;
        } else if (crossProjectCount > 0) {
            statusBadge = `<span class="badge badge-warning">跨项目命中</span>`;
            statusTitle = `有 ${crossProjectCount} 个指纹属于其他项目`;
        } else {
            statusBadge = `<span class="badge badge-muted">未匹配</span>`;
            statusTitle = '未找到泄露源';
        }

        // 跨项目提示
        let crossProjectHint = '';
        if (crossProjectCount > 0) {
            crossProjectHint = `
                <p class="text-sm text-secondary mt-3" style="padding:var(--space-3);background:var(--color-bg);border-radius:var(--radius)">
                    另有 <strong>${crossProjectCount}</strong> 个指纹属于其他项目，无法查看其下载者信息。
                </p>
            `;
        }

        result.innerHTML = `
            <div class="card">
                <div class="card-title">
                    ${statusBadge}
                    &nbsp;${statusTitle}
                </div>
                <p class="text-sm text-secondary">
                    取证文件：<strong>${escapeHtml(file.name)}</strong>
                    ${totalCount > 0 ? `（共 ${totalCount} 个指纹匹配）` : ''}
                </p>
                ${matchesHtml}
                ${crossProjectHint}
                ${leakerCount > 0 ? `
                    <button class="btn btn-primary mt-4" id="forensics-report-btn">下载取证报告（PDF）</button>
                ` : ''}
            </div>
        `;

        // 绑定报告下载按钮
        const reportBtn = document.getElementById('forensics-report-btn');
        if (reportBtn) {
            reportBtn.addEventListener('click', () => downloadForensicsReport(pid, file));
        }

    } catch (err) {
        result.innerHTML = `<div class="card" style="color:var(--color-danger)">${escapeHtml(err.message)}</div>`;
    }
}

async function downloadForensicsReport(pid, file) {
    try {
        const fd = new FormData();
        fd.append('file', file);
        const resp = await api(`/project/${pid}/forensics/report`, { method: 'POST', body: fd });
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const ct = resp.headers.get('Content-Type') || '';
        const ext = ct.includes('pdf') ? 'pdf' : 'txt';
        const prefix = (file.name || '').replace(/\.[^.]+$/, '') || 'forensics';
        a.download = `取证报告_${prefix}.${ext}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast('报告已下载', 'success');
    } catch (err) {
        toast(err.message || '下载失败', 'error');
    }
}