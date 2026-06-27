// 通用 UI 辅助：Toast / Modal / 时间格式化 / 转义

function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function formatTime(iso) {
    if (!iso) return '-';
    try {
        const d = new Date(iso);
        const pad = n => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
    } catch (_) {
        return iso;
    }
}

function shortHash(h, len = 16) {
    if (!h) return '-';
    return h.length > len ? h.substring(0, len) + '…' : h;
}

function copyText(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => toast('已复制到剪贴板', 'success'));
    } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        toast('已复制到剪贴板', 'success');
    }
}

// Toast
function ensureToastContainer() {
    let c = document.getElementById('toast-container');
    if (!c) {
        c = document.createElement('div');
        c.id = 'toast-container';
        c.className = 'toast-container';
        document.body.appendChild(c);
    }
    return c;
}
function toast(msg, type = 'info') {
    const c = ensureToastContainer();
    const t = document.createElement('div');
    t.className = 'toast toast-' + type;
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => {
        t.style.transition = 'opacity 0.3s';
        t.style.opacity = '0';
        setTimeout(() => t.remove(), 300);
    }, 2700);
}

// Modal
function openModal(title, bodyHtml, opts = {}) {
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal">
                <div class="modal-title">${escapeHtml(title)}</div>
                <div class="modal-body">${bodyHtml}</div>
                <div class="modal-actions">
                    <button class="btn btn-secondary" data-action="cancel">${escapeHtml(opts.cancelText || '取消')}</button>
                    <button class="btn ${opts.dangerous ? 'btn-danger' : 'btn-primary'}" data-action="ok">${escapeHtml(opts.okText || '确定')}</button>
                </div>
            </div>
        `;
        document.body.appendChild(overlay);

        const close = (result) => {
            overlay.remove();
            resolve(result);
        };

        // 关键修复：只有 mousedown 和 click target 都落在背景上才算"点击背景关闭"。
        // 原本只看 click target，但 click 事件的 target 在 mousedown 与 mouseup
        // 落在不同子元素时会退化为最近公共祖先 —— 这正是日期选择器在 input 上
        // mousedown、在弹出的 picker 上 mouseup 时触发模态误关闭的根因。
        let mousedownOnOverlay = false;
        overlay.addEventListener('mousedown', (e) => {
            mousedownOnOverlay = (e.target === overlay);
        });
        overlay.addEventListener('click', (e) => {
            const backdropClick = (e.target === overlay) && mousedownOnOverlay;
            mousedownOnOverlay = false;
            if (backdropClick) { close(null); return; }
            if (e.target.dataset.action === 'cancel') { close(null); return; }
            if (e.target.dataset.action === 'ok') {
                const formData = {};
                overlay.querySelectorAll('[name]').forEach(el => {
                    // radio/checkbox 只取 checked 的项，避免同 name 多元素时值被覆盖
                    if (el.type === 'radio' || el.type === 'checkbox') {
                        if (el.checked) formData[el.name] = el.value;
                    } else {
                        formData[el.name] = el.value;
                    }
                });
                close(formData);
            }
        });

        // 自动聚焦第一个输入
        const first = overlay.querySelector('input, select, textarea');
        if (first) first.focus();
    });
}

function confirmDialog(title, message, opts = {}) {
    return openModal(title, `<p>${escapeHtml(message)}</p>`, Object.assign({ dangerous: true, okText: '确认' }, opts));
}

// 加载占位
function loadingHtml(text = '加载中…') {
    return `<div class="loading"><div class="spinner"></div>&nbsp;&nbsp;${escapeHtml(text)}</div>`;
}

function emptyState(title, desc, actionHtml = '') {
    return `
        <div class="empty-state">
            <div class="empty-state-title">${escapeHtml(title)}</div>
            ${desc ? `<div class="empty-state-desc">${escapeHtml(desc)}</div>` : ''}
            ${actionHtml}
        </div>
    `;
}

// 文件类型 → 中文
const FILE_TYPE_LABEL = {
    pdf:    'PDF',
    docx:   'Word',
    image:  '图片',
    text:   '文本',
    code:   '代码',
    csv:    'CSV',
    excel:  'Excel',
    data:   '数据库',
    ppt:    'PPT',
    video:  '视频',
    audio:  '音频',
    zip:    '压缩包',
    binary: '可执行',
    other:  '其他',
};
function fileTypeLabel(t) {
    return FILE_TYPE_LABEL[t] || (t || '其他');
}

// 绑定一个 "X/MAX" 字数计数器到 input/textarea
function bindCharCounter(inputId, counterId, max) {
    const input = document.getElementById(inputId);
    const counter = document.getElementById(counterId);
    if (!input || !counter) return;
    const update = () => {
        const len = [...(input.value || '')].length;  // 用 spread 算 codepoint，符合"30 个汉字"语义
        counter.textContent = `${len}/${max}`;
        counter.style.color = len >= max ? 'var(--color-danger)' : '';
    };
    update();
    input.addEventListener('input', update);
}

function fileSizeStr(bytes) {
    if (bytes == null) return '-';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
    return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}

// ===== 自定义日期+时间选择器 =====
// 用法：bindDatePicker(inputEl, { initial: Date, min: Date })
// 输入框只读，点击切换面板；选定后写回 input.value 为 "YYYY-MM-DD HH:mm"
//
// 配合 openModal 的 mousedown 起点追踪修复，这里只需要保证：
// 1) 在 readonly input 上 mousedown 时 preventDefault 抑制 focus / selection
// 2) click 时切换 picker，并阻止冒泡到 modal-overlay
function bindDatePicker(input, opts = {}) {
    input.readOnly = true;
    input.classList.add('dp-trigger');
    input.addEventListener('mousedown', (e) => {
        e.preventDefault();
    });
    input.addEventListener('click', (e) => {
        e.stopPropagation();
        const existing = document.querySelector('.date-picker-pop');
        if (existing) {
            existing.remove();
        } else {
            openDatePicker(input, opts);
        }
    });
}

function parseDpValue(v) {
    if (!v) return null;
    // 接受 "YYYY-MM-DD HH:mm" 或 ISO
    const m = /^(\d{4})-(\d{1,2})-(\d{1,2})[ T](\d{1,2}):(\d{1,2})/.exec(v);
    if (m) return new Date(+m[1], +m[2]-1, +m[3], +m[4], +m[5]);
    const d = new Date(v);
    return isNaN(d) ? null : d;
}

function fmtDpValue(d) {
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function openDatePicker(input, opts = {}) {
    // 已开则关
    document.querySelectorAll('.date-picker-pop').forEach(el => el.remove());

    const min = opts.min instanceof Date ? opts.min : null;
    let current = parseDpValue(input.value) || (opts.initial instanceof Date ? new Date(opts.initial) : new Date(Date.now() + 7 * 86400000));
    let viewMonth = new Date(current.getFullYear(), current.getMonth(), 1);

    // 容器：优先挂到当前 modal-overlay 上，避免 modal 关闭后 picker 残留
    const container = input.closest('.modal-overlay') || document.body;
    const pop = document.createElement('div');
    pop.className = 'date-picker-pop';
    container.appendChild(pop);

    function position() {
        const rect = input.getBoundingClientRect();
        const popH = pop.offsetHeight || 320;
        // 默认在输入框下方；空间不足则上翻
        let top = rect.bottom + 6;
        if (top + popH > window.innerHeight - 8) {
            top = Math.max(8, rect.top - popH - 6);
        }
        let left = rect.left;
        const popW = pop.offsetWidth || 280;
        if (left + popW > window.innerWidth - 8) {
            left = Math.max(8, window.innerWidth - popW - 8);
        }
        pop.style.top = top + 'px';
        pop.style.left = left + 'px';
    }

    function isSameDay(a, b) {
        return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
    }

    function render() {
        const year = viewMonth.getFullYear();
        const month = viewMonth.getMonth();
        const firstDay = new Date(year, month, 1).getDay();
        const daysInMonth = new Date(year, month + 1, 0).getDate();
        const daysInPrev = new Date(year, month, 0).getDate();
        const today = new Date();

        const cells = [];
        for (let i = firstDay - 1; i >= 0; i--) {
            cells.push({ d: daysInPrev - i, kind: 'prev' });
        }
        for (let d = 1; d <= daysInMonth; d++) {
            cells.push({ d, kind: 'cur' });
        }
        while (cells.length < 42) {
            cells.push({ d: cells.length - daysInMonth - firstDay + 1, kind: 'next' });
        }

        pop.innerHTML = `
            <div class="dp-header">
                <button type="button" class="dp-nav" data-act="prev-year" title="上一年">«</button>
                <button type="button" class="dp-nav" data-act="prev-month" title="上一月">‹</button>
                <div class="dp-title">${year} 年 ${month + 1} 月</div>
                <button type="button" class="dp-nav" data-act="next-month" title="下一月">›</button>
                <button type="button" class="dp-nav" data-act="next-year" title="下一年">»</button>
            </div>
            <div class="dp-grid">
                ${['日','一','二','三','四','五','六'].map(w => `<div class="dp-weekday">${w}</div>`).join('')}
                ${cells.map(c => {
                    const day = c.kind === 'cur' ? c.d : (c.kind === 'prev' ? c.d : c.d);
                    const dDate = c.kind === 'cur'
                        ? new Date(year, month, day)
                        : (c.kind === 'prev' ? new Date(year, month - 1, day) : new Date(year, month + 1, day));
                    const sel = isSameDay(dDate, current);
                    const isToday = isSameDay(dDate, today);
                    const disabled = min && dDate < new Date(min.getFullYear(), min.getMonth(), min.getDate());
                    return `<button type="button" class="dp-cell ${c.kind!=='cur'?'dp-other':''} ${sel?'dp-selected':''} ${isToday?'dp-today':''} ${disabled?'dp-disabled':''}"
                                ${disabled?'disabled':''}
                                data-y="${dDate.getFullYear()}" data-m="${dDate.getMonth()}" data-d="${dDate.getDate()}">${day}</button>`;
                }).join('')}
            </div>
            <div class="dp-time">
                <span class="dp-time-label">时间</span>
                <input class="dp-time-input" type="number" min="0" max="23" data-part="h" value="${String(current.getHours()).padStart(2,'0')}">
                <span class="dp-time-sep">:</span>
                <input class="dp-time-input" type="number" min="0" max="59" data-part="m" value="${String(current.getMinutes()).padStart(2,'0')}">
            </div>
            <div class="dp-footer">
                <button type="button" class="dp-quick" data-quick="1h">+1 小时</button>
                <button type="button" class="dp-quick" data-quick="1d">+1 天</button>
                <button type="button" class="dp-quick" data-quick="7d">+1 周</button>
                <button type="button" class="dp-quick" data-quick="30d">+1 月</button>
            </div>
            <div class="dp-actions">
                <button type="button" class="btn btn-secondary btn-sm" data-act="cancel">取消</button>
                <button type="button" class="btn btn-primary btn-sm" data-act="ok">确定</button>
            </div>
        `;
        position();
    }

    function close() {
        pop.remove();
        document.removeEventListener('mousedown', onDocDown, true);
        window.removeEventListener('resize', position);
        window.removeEventListener('scroll', position, true);
    }

    function commit() {
        input.value = fmtDpValue(current);
        input.dispatchEvent(new Event('change', { bubbles: true }));
        close();
    }

    function onDocDown(e) {
        if (pop.contains(e.target) || e.target === input) return;
        close();
    }

    // 关键：彻底拦截 picker 内部的 mousedown / click 冒泡，
    // 避免冒到外层 modal-overlay 的 click 监听器导致 modal 误关闭。
    pop.addEventListener('mousedown', (e) => e.stopPropagation());
    pop.addEventListener('click', (e) => e.stopPropagation());

    pop.addEventListener('click', (e) => {
        const act = e.target.dataset?.act;
        const quick = e.target.dataset?.quick;
        if (act === 'prev-month') { viewMonth.setMonth(viewMonth.getMonth() - 1); render(); return; }
        if (act === 'next-month') { viewMonth.setMonth(viewMonth.getMonth() + 1); render(); return; }
        if (act === 'prev-year')  { viewMonth.setFullYear(viewMonth.getFullYear() - 1); render(); return; }
        if (act === 'next-year')  { viewMonth.setFullYear(viewMonth.getFullYear() + 1); render(); return; }
        if (act === 'cancel') { close(); return; }
        if (act === 'ok')     { commit(); return; }
        if (quick) {
            const base = new Date();
            const map = { '1h': 3600000, '1d': 86400000, '7d': 7 * 86400000, '30d': 30 * 86400000 };
            current = new Date(base.getTime() + map[quick]);
            viewMonth = new Date(current.getFullYear(), current.getMonth(), 1);
            render();
            return;
        }
        const cell = e.target.closest('.dp-cell');
        if (cell && !cell.disabled) {
            const y = +cell.dataset.y, mo = +cell.dataset.m, dd = +cell.dataset.d;
            current = new Date(y, mo, dd, current.getHours(), current.getMinutes());
            viewMonth = new Date(y, mo, 1);
            render();
        }
    });

    pop.addEventListener('input', (e) => {
        const part = e.target.dataset?.part;
        if (part === 'h') {
            const h = Math.max(0, Math.min(23, parseInt(e.target.value) || 0));
            current.setHours(h);
        } else if (part === 'm') {
            const m = Math.max(0, Math.min(59, parseInt(e.target.value) || 0));
            current.setMinutes(m);
        }
    });

    render();
    setTimeout(() => {
        document.addEventListener('mousedown', onDocDown, true);
        window.addEventListener('resize', position);
        window.addEventListener('scroll', position, true);
    }, 0);
}

function roleBadge(role) {
    const map = {
        owner:   ['负责人', 'badge-info'],
        member:  ['成员',   'badge-muted'],
        partner: ['合作方', 'badge-warning'],
        auditor: ['审计员', 'badge-success'],
    };
    const [label, cls] = map[role] || [role, 'badge-muted'];
    return `<span class="badge ${cls}">${label}</span>`;
}

function statusBadge(status) {
    const map = {
        valid:    ['有效',   'badge-success'],
        revoked:  ['已撤销', 'badge-danger'],
        expired:  ['已过期', 'badge-muted'],
        active:   ['活跃',   'badge-success'],
        removed:  ['已移除', 'badge-muted'],
        success:  ['成功',   'badge-success'],
        denied:   ['拒绝',   'badge-danger'],
        failed:   ['失败',   'badge-danger'],
    };
    const [label, cls] = map[status] || [status, 'badge-muted'];
    return `<span class="badge ${cls}">${label}</span>`;
}
