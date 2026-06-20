// 泄露取证（全局）

async function renderForensics(root) {
    root.innerHTML = `
        <div class="page-header">
            <div>
                <div class="page-title">泄露取证</div>
                <div class="page-subtitle">上传疑似泄露的文件，平台将根据数字水印指纹追溯泄露源头</div>
            </div>
        </div>

        <div class="card">
            <div class="upload-zone" id="upload-zone">
                <div class="upload-zone-title">📄 拖拽文件到这里 或 点击选择文件</div>
                <div class="upload-zone-hint">支持 PDF / DOCX / 图片等格式</div>
                <input type="file" id="forensics-file" style="display:none">
            </div>
        </div>

        <div id="forensics-result" class="mt-4"></div>
    `;

    const zone = document.getElementById('upload-zone');
    const fileInput = document.getElementById('forensics-file');

    zone.addEventListener('click', () => fileInput.click());
    zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            handleForensics(e.dataTransfer.files[0]);
        }
    });
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) handleForensics(e.target.files[0]);
    });
}

async function handleForensics(file) {
    const result = document.getElementById('forensics-result');
    result.innerHTML = `<div class="card">${loadingHtml('正在分析文件指纹…')}</div>`;
    try {
        const fd = new FormData();
        fd.append('file', file);
        const r = await apiUpload('/file/forensics', fd);

        if (r.matched) {
            result.innerHTML = `
                <div class="card">
                    <div class="card-title">
                        <span class="badge badge-danger">已匹配</span>
                        &nbsp;追溯到泄露源
                    </div>
                    <div class="form-group">
                        <label class="form-label">泄露用户</label>
                        <div><strong>${escapeHtml(r.username || '-')}</strong></div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">下载时间</label>
                        <div>${formatTime(r.download_time)}</div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">水印类型</label>
                        <div>${escapeHtml(r.watermark_type)}</div>
                    </div>
                    <div class="form-group">
                        <label class="form-label">指纹</label>
                        <div class="text-mono hash-cell" onclick="copyText('${escapeHtml(r.fingerprint || '')}')" title="点击复制">${shortHash(r.fingerprint, 32)}</div>
                    </div>
                    <button class="btn btn-primary" id="download-report-btn">下载取证报告（PDF）</button>
                </div>
            `;
            document.getElementById('download-report-btn').addEventListener('click', () => downloadReport(file));
        } else {
            result.innerHTML = `
                <div class="card">
                    <div class="card-title">
                        <span class="badge badge-muted">未匹配</span>
                    </div>
                    <p>${escapeHtml(r.message || '未找到匹配的水印指纹，无法追溯来源')}</p>
                </div>
            `;
        }
    } catch (err) {
        result.innerHTML = `<div class="card" style="color:var(--color-danger)">${escapeHtml(err.message)}</div>`;
    }
}

async function downloadReport(file) {
    try {
        const fd = new FormData();
        fd.append('file', file);
        const resp = await api('/file/forensics/report', { method: 'POST', body: fd });
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'forensics_report.pdf';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        toast('报告已下载', 'success');
    } catch (err) {
        toast(err.message || '下载失败', 'error');
    }
}
