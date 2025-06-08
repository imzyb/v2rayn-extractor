const express = require('express');
const multer = require('multer');
const yaml = require('js-yaml');
const axios = require('axios'); // 用于从URL获取订阅内容
const path = require('path');
const { URLSearchParams } = require('url'); // Node.js 内置
const { Buffer } = require('buffer'); // Node.js 内置

const app = express();
const port = 3000;

// 使用 multer 来处理文件上传。'file' 是前端 input 标签的 name。
const upload = multer({ storage: multer.memoryStorage() });

// --- 核心逻辑函数 (从我们之前的JS代码迁移过来) ---

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

// --- API 路由和静态文件服务 ---

// 1. 提供静态文件服务 (将 public 目录下的文件作为网站内容)
app.use(express.static(path.join(__dirname, 'public')));

// 2. 创建 API 接口，用于处理节点提取请求
// 我们使用 upload.single('file') 来接收上传的文件
app.post('/api/extract', upload.single('file'), async (req, res) => {
    const { inputType, url } = req.body;
    let content = '';

    try {
        if (inputType === 'url') {
            if (!url) {
                return res.status(400).send('错误：未提供URL。');
            }
            const response = await axios.get(url, { headers: { 'User-Agent': 'Clash' } });
            content = response.data;
        } else if (inputType === 'file') {
            if (!req.file) {
                return res.status(400).send('错误：未提供文件。');
            }
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

// 启动服务器
app.listen(port, () => {
    console.log(`服务器正在 http://localhost:${port} 上运行`);
});