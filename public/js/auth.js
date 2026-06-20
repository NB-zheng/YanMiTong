// Token / 会话管理（不保存公钥、不保存 user_id；统一以 username 为身份）

function saveSession(data) {
    localStorage.setItem('token', data.token);
    localStorage.setItem('username', data.username);
}

function getToken() {
    return localStorage.getItem('token');
}

function getUsername() {
    return localStorage.getItem('username') || '';
}

function clearSession() {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
}

async function logout() {
    try {
        await apiPost('/auth/logout', {});
    } catch (e) {
        // 即便后端清理失败，前端也强制清理
    }
    clearSession();
    window.location.href = '/login.html';
}
