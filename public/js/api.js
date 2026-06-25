// 统一 API 封装

const API_BASE = '/api';

async function api(path, options = {}) {
    const token = getToken();
    const headers = Object.assign({}, options.headers || {});
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }
    if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
    }

    const resp = await fetch(API_BASE + path, Object.assign({}, options, { headers }));

    if (resp.status === 401) {
        clearSession();
        if (location.pathname !== '/login.html' && location.pathname !== '/register.html') {
            window.location.href = '/login.html';
        }
        throw new Error('未授权');
    }
    if (!resp.ok) {
        let detail = '请求失败';
        try {
            const err = await resp.json();
            detail = err.detail || detail;
        } catch (_) {}
        throw new Error(detail);
    }
    return resp;
}

async function apiGet(path) {
    return (await api(path)).json();
}

async function apiPost(path, body) {
    return (await api(path, {
        method: 'POST',
        body: JSON.stringify(body || {}),
    })).json();
}

async function apiDelete(path) {
    return (await api(path, { method: 'DELETE' })).json();
}

async function apiUpload(path, formData) {
    return (await api(path, {
        method: 'POST',
        body: formData,
    })).json();
}

// 带进度回调的上传：网络阶段触发 onProgress({phase:'upload', percent}),
// 上传完字节后服务端还要做 SM3/SM4，触发 onProgress({phase:'server'})。
function apiUploadWithProgress(path, formData, onProgress) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', API_BASE + path);
        const token = getToken();
        if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);

        xhr.upload.onprogress = (e) => {
            if (!onProgress || !e.lengthComputable) return;
            const percent = Math.round((e.loaded / e.total) * 100);
            onProgress({ phase: 'upload', percent });
        };
        xhr.upload.onload = () => {
            if (onProgress) onProgress({ phase: 'server' });
        };
        xhr.onerror = () => reject(new Error('网络错误'));
        xhr.onabort = () => reject(new Error('上传已取消'));
        xhr.onload = () => {
            if (xhr.status === 401) {
                clearSession();
                if (location.pathname !== '/login.html' && location.pathname !== '/register.html') {
                    window.location.href = '/login.html';
                }
                return reject(new Error('未授权'));
            }
            if (xhr.status < 200 || xhr.status >= 300) {
                let detail = '上传失败';
                try { detail = JSON.parse(xhr.responseText).detail || detail; } catch (_) {}
                return reject(new Error(detail));
            }
            try { resolve(JSON.parse(xhr.responseText)); }
            catch (_) { resolve({}); }
        };
        xhr.send(formData);
    });
}

async function apiDownload(path) {
    return api(path);
}

// 文件下载（含中文文件名解析）
async function downloadFileById(fileId) {
    const resp = await apiDownload(`/file/${fileId}/download`);
    const disposition = resp.headers.get('Content-Disposition') || '';
    let filename = 'download';
    const m = disposition.match(/filename\*=UTF-8''([^;]+)/);
    if (m) {
        try { filename = decodeURIComponent(m[1]); } catch (_) {}
    } else {
        const m2 = disposition.match(/filename="([^"]+)"/);
        if (m2) filename = m2[1];
    }
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
