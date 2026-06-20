// 关于页：团队信息

const TEAM = [
    {
        name: '黄智超',
        role: '核心加密',
        desc: '设计并实现 SM2 / SM3 / SM4 国密原语，含 SM4 文件加密、SM2 密钥封装、SM3 哈希链等底层算法实现。',
        accent: '#C96442',
    },
    {
        name: '郑志轩',
        role: '后端开发',
        desc: '搭建 FastAPI 服务框架，设计数据模型与 API 契约，实现授权撤销、审计链、水印取证等业务流程。',
        accent: '#5B7FA5',
    },
    {
        name: '汪金',
        role: '前端开发',
        desc: '实现前端所有交互页面：项目管理、文件加解密、授权审计、用户中心；自定义日期组件等。',
        accent: '#3D8C6F',
    },
    {
        name: '梁开新',
        role: '项目协调与文档',
        desc: '撰写项目报告与技术文档，协调团队成员分工与节奏，把控项目整体进度。',
        accent: '#D4910A',
    },
];

async function renderAbout(root) {
    root.innerHTML = `
        <div class="page-header">
            <div>
                <div class="page-title">关于</div>
                <div class="page-subtitle">研密通 · 面向高校科研数据的国产密码可信共享与审计平台</div>
            </div>
        </div>

        <div class="card mb-6 about-intro">
            <div class="about-intro-title">关于研密通</div>
            <p class="about-intro-text">
                研密通是一个基于国密算法（SM2 / SM3 / SM4）的科研数据可信共享系统：
                文件以 SM4 对称加密落盘，密钥用 SM2 公钥逐人封装；下载时嵌入用户身份数字水印，
                SM3 哈希链保证审计日志不可篡改，强撤销机制保证授权可被真正回收。
            </p>
        </div>

        <div class="page-section-title">团队成员</div>
        <div class="grid grid-cols-2 about-team">
            ${TEAM.map(m => `
                <div class="about-card" style="--member-accent:${m.accent}">
                    <div class="about-card-head">
                        <div class="about-avatar" style="background:${m.accent}">${escapeHtml(m.name[0])}</div>
                        <div>
                            <div class="about-name">${escapeHtml(m.name)}</div>
                            <div class="about-role">${escapeHtml(m.role)}</div>
                        </div>
                    </div>
                    <div class="about-desc">${escapeHtml(m.desc)}</div>
                </div>
            `).join('')}
        </div>

        <div class="text-center text-muted text-sm mt-6">
            © 2026 研密通项目组 · Made with 国密之力
        </div>
    `;
}
