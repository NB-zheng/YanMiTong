// 用户信息页：用户名 / 单位 / 密码 三个字段各自带修改按钮

const PENCIL_ICON_SVG = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" width="16" height="16">
        <path d="M14.5 4.5l5 5"/>
        <path d="M4 20l4-1 11-11-3-3-11 11-1 4z"/>
    </svg>
`;

async function renderProfile(root) {
    root.innerHTML = `
        <div class="page-header">
            <div>
                <div class="page-title">用户信息</div>
                <div class="page-subtitle">查看并修改你的账户信息</div>
            </div>
        </div>

        <div class="card" style="max-width:560px">
            <div id="profile-fields">${loadingHtml()}</div>
        </div>
    `;

    await loadProfile();
}

async function loadProfile() {
    const c = document.getElementById('profile-fields');
    try {
        const me = await apiGet('/auth/me');
        c.innerHTML = `
            ${profileRow('用户名', escapeHtml(me.username), 'edit-username')}
            ${profileRow('所属单位', escapeHtml(me.organization || '未填写'), 'edit-org')}
            ${profileRow('密码', '••••••••', 'edit-password')}
            ${profileRow('注册时间', formatTime(me.created_time), null)}
        `;
        document.getElementById('edit-username').addEventListener('click', () => editUsername(me.username));
        document.getElementById('edit-org').addEventListener('click', () => editOrganization(me.organization));
        document.getElementById('edit-password').addEventListener('click', () => editPassword());
    } catch (err) {
        c.innerHTML = `<div style="color:var(--color-danger)">${escapeHtml(err.message)}</div>`;
    }
}

function profileRow(label, value, editId) {
    return `
        <div class="profile-row">
            <div class="profile-label">${escapeHtml(label)}</div>
            <div class="profile-value">${value}</div>
            ${editId ? `<button class="profile-edit" id="${editId}" title="修改" aria-label="修改${escapeHtml(label)}">${PENCIL_ICON_SVG}</button>` : '<div></div>'}
        </div>
    `;
}

// ===== 修改用户名 =====
async function editUsername(current) {
    const body = `
        <div class="form-group">
            <label class="form-label">新用户名</label>
            <input class="input" type="text" name="username" required minlength="2" maxlength="50" value="${escapeHtml(current)}" autocomplete="off">
            <div class="text-sm text-muted mt-2">用户名变更后会立即生效；其它人原来认识你的旧名将看到新名。</div>
        </div>
    `;
    const r = await openModal('修改用户名', body, { okText: '保存' });
    if (!r) return;
    const username = (r.username || '').trim();
    if (!username || username === current) return;
    try {
        const updated = await api('/auth/me', {
            method: 'PUT',
            body: JSON.stringify({ username }),
        }).then(r => r.json());
        localStorage.setItem('username', updated.username);
        // 同步左侧栏显示
        const nameEl = document.getElementById('user-name');
        if (nameEl) nameEl.textContent = updated.username;
        toast('用户名已更新', 'success');
        loadProfile();
    } catch (err) {
        toast(err.message || '修改失败', 'error');
    }
}

// ===== 修改所属单位 =====
async function editOrganization(current) {
    const body = `
        <div class="form-group">
            <label class="form-label">所属单位</label>
            <input class="input" type="text" name="organization" maxlength="100" value="${escapeHtml(current || '')}" placeholder="留空表示清除">
        </div>
    `;
    const r = await openModal('修改所属单位', body, { okText: '保存' });
    if (!r) return;
    const organization = (r.organization || '').trim();
    if (organization === (current || '')) return;
    try {
        await api('/auth/me', {
            method: 'PUT',
            body: JSON.stringify({ organization }),
        });
        toast('所属单位已更新', 'success');
        loadProfile();
    } catch (err) {
        toast(err.message || '修改失败', 'error');
    }
}

// ===== 修改密码 =====
async function editPassword() {
    const body = `
        <div class="form-group">
            <label class="form-label">当前密码</label>
            <input class="input" type="password" name="old_password" required autocomplete="current-password">
        </div>
        <div class="form-group">
            <label class="form-label">新密码</label>
            <input class="input" type="password" name="new_password" required minlength="6" maxlength="64" autocomplete="new-password">
        </div>
        <div class="form-group">
            <label class="form-label">确认新密码</label>
            <input class="input" type="password" name="new_password2" required minlength="6" maxlength="64" autocomplete="new-password">
            <div class="text-sm text-muted mt-2">密码修改成功后需要重新登录</div>
        </div>
    `;
    const r = await openModal('修改密码', body, { okText: '保存' });
    if (!r) return;
    if (!r.old_password || !r.new_password) {
        toast('请填写完整', 'error');
        return;
    }
    if (r.new_password !== r.new_password2) {
        toast('两次输入的新密码不一致', 'error');
        return;
    }
    if (r.new_password === r.old_password) {
        toast('新密码不能与当前密码相同', 'warning');
        return;
    }
    try {
        await apiPost('/auth/change-password', {
            old_password: r.old_password,
            new_password: r.new_password,
        });
        toast('密码已更新，1.2 秒后跳转到登录页…', 'success');
        setTimeout(() => {
            clearSession();
            window.location.href = '/login.html';
        }, 1200);
    } catch (err) {
        toast(err.message || '修改失败', 'error');
    }
}
