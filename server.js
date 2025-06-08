const express = require('express');
const multer = require('multer');
const yaml = require('js-yaml');
const axios = require('axios');
const path = require('path');
const { URLSearchParams } = require('url');
const { Buffer } = require('buffer');

const app = express();
const port = 3000;

const upload = multer({ storage: multer.memoryStorage() });

// --- 核心逻辑函数 ---

function extractNodesFromYamlContent(content) {
    try {
        const data = yaml.load(content);
        return (data && data.proxies && Array.isArray(data.proxies)) ? data.proxies : [];
    } catch (e) {
        return [];
    }
}

function generateShareLinks(nodes) {
    const shareLinks = [];
    for (const node of nodes) {
        let link = '';
        try {
            const type = (node.type || '').toLowerCase();
            const remarks = encodeURIComponent(node.name || 'N/A');
            const server = node.server;
            const port = node.port;

            if (type === 'vless' && node.uuid && server && port) {
                const params = new URLSearchParams();
                if (node.network) params.set('type', node.network);
                if (node.security) params.set('security', node.security);
                if (node.flow) params.set('flow', node.flow);
                if (node.sni || node.servername) params.set('sni', node.sni || node.servername);
                link = `vless://${node.uuid}@${server}:${port}?${params.toString()}#${remarks}`;
            } else if (type === 'vmess') {
                const vmessConfig = {
                    v: '2', ps: node.name || 'N/A', add: server, port: port, id: node.uuid,
                    aid: node.alterId || 0, scy: node.cipher || 'auto', net: node.network || 'tcp',
                    type: 'none', host: node['ws-opts']?.host || '', path: node['ws-opts']?.path || '',
                    tls: node.tls ? 'tls' : '',
                };
                const jsonConfig = JSON.stringify(Object.fromEntries(Object.entries(vmessConfig).filter(([_, v]) => v)));
                link = `vmess://${Buffer.from(jsonConfig).toString('base64')}`;
            } else if ((type === 'ss' || type === 'shadowsocks') && node.cipher && node.password) {
                const credentials = `${node.cipher}:${node.password}`;
                const encodedCreds = Buffer.from(credentials).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
                link = `ss://${encodedCreds}@${server}:${port}#${remarks}`;
            } else if (type === 'trojan' && node.password && server && port) {
                const params = new URLSearchParams();
                if (node.sni || node.servername) params.set('sni', node.sni || node.servername);
                if (node.alpn?.length) params.set('alpn', node.alpn.join(','));
                link = `trojan://${node.password}@${server}:${port}?${params.toString()}#${remarks}`;
            }
            if (link) shareLinks.push(link);
        } catch (e) { console.error(`为节点 ${node.name} 生成链接时失败:`, e); }
    }
    return shareLinks.join('\n');
}

// --- API 路由 ---

// Vercel 会自动处理静态文件，这里我们只定义 API
app.post('/api/extract', upload.single('file'), async (req, res) => {
    // 注意: Vercel 需要 express.urlencoded() 来解析表单的 URL 部分
    express.urlencoded({ extended: true })(req, res, async () => {
        const { inputType, url } = req.body;
        let content = '';

        try {
            if (inputType === 'url') {
                if (!url) return res.status(400).send('错误：未提供URL。');
                const response = await axios.get(url, { headers: { 'User-Agent': 'Clash' } });
                content = response.data;
            } else if (inputType === 'file') {
                if (!req.file) return res.status(400).send('错误：未提供文件。');
                content = req.file.buffer.toString('utf8');
            } else {
                return res.status(400).send('错误：无效的输入类型。');
            }

            let nodes = [];
            try {
                nodes = extractNodesFromYamlContent(Buffer.from(content, 'base64').toString('utf8'));
            } catch (e) {
                nodes = extractNodesFromYamlContent(content);
            }
            
            if (nodes.length === 0) {
                 nodes = extractNodesFromYamlContent(content);
            }

            if (nodes.length === 0) {
                return res.status(400).send('错误：在提供的数据中未能找到任何代理节点。');
            }

            const shareLinks = generateShareLinks(nodes);
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.status(200).send(shareLinks);

        } catch (error) {
            console.error('处理错误:', error.message);
            res.status(500).send(`服务器错误: ${error.message}`);
        }
    });
});

// 在本地开发时，需要一个根路由来提供index.html
if (process.env.VERCEL !== '1') {
    app.use(express.static(path.join(__dirname, 'public')));
}

// 导出 app 供 Vercel 使用
module.exports = app;
