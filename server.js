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

// [重要修改] 更新了 VLESS 节点的生成逻辑
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
                
                // 处理 network
                if (node.network) {
                    params.set('type', node.network);
                }

                // 处理 security (tls, reality)
                if (node.tls) {
                    // 检查是否存在 reality-opts 来判断是 tls 还是 reality
                    if (node['reality-opts'] && node['reality-opts']['public-key']) {
                        params.set('security', 'reality');
                        // 处理 reality 参数
                        if (node['reality-opts']['public-key']) {
                            params.set('pbk', node['reality-opts']['public-key']);
                        }
                        if (node['reality-opts']['short-id']) {
                            params.set('sid', node['reality-opts']['short-id']);
                        }
                    } else {
                        params.set('security', 'tls');
                    }
                }
                
                // 处理 flow
                if (node.flow) {
                    params.set('flow', node.flow);
                }

                // 处理 fingerprint
                if (node['client-fingerprint']) {
                    params.set('fp', node['client-fingerprint']);
                }

                // 处理 sni
                if (node.servername || node.sni) {
                    params.set('sni', node.servername || node.sni);
                }

                // 处理 WebSocket (ws) 参数
                if (node.network === 'ws' && node['ws-opts']) {
                    if (node['ws-opts']['path']) {
                        params.set('path', node['ws-opts']['path']);
                    }
                    if (node['ws-opts']['headers'] && node['ws-opts']['headers']['Host']) {
                        params.set('host', node['ws-opts']['headers']['Host']);
                    }
                }

                // 基础链接
                link = `vless://${node.uuid}@${server}:${port}?${params.toString()}#${remarks}`;

            } else if (type === 'vmess') {
                const vmessConfig = {
                    v: '2', ps: node.name || 'N/A', add: server, port: port, id: node.uuid,
                    aid: node.alterId || 0, scy: node.cipher || 'auto', net: node.network || 'tcp',
                    type: 'none', host: node['ws-opts']?.host || node['http-opts']?.headers?.Host?.[0] || '', path: node['ws-opts']?.path || node['http-opts']?.path?.[0] || '',
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
            
            } else if ((type === 'hysteria' || type === 'hysteria2') && server && port) {
                 const auth = node.auth || node.auth_str || node.password;
                 if(auth) {
                    const params = new URLSearchParams();
                    params.set('sni', node.sni || node.servername || '');
                    if (node['skip-cert-verify']) params.set('insecure', '1');
                    if (node.up) params.set('up', node.up.toString().replace(/\s*mbps\s*/i, ''));
                    if (node.down) params.set('down', node.down.toString().replace(/\s*mbps\s*/i, ''));
                    if (node.obfs) params.set('obfs', node.obfs);
                    if (node['obfs-password']) params.set('obfs-password', node['obfs-password']);

                    const query = Array.from(params.entries()).filter(([_, v]) => v).map(([k, v]) => `${k}=${v}`).join('&');
                    link = `${type}://${server}:${port}?${query}#${remarks}`;
                 }
            }
            
            if (link) shareLinks.push(link);
        } catch (e) { console.error(`为节点 ${node.name} 生成链接时失败:`, e); }
    }
    return shareLinks.join('\n');
}


// --- API 路由 ---

app.use(express.urlencoded({ extended: true }));

app.post('/api/extract', upload.single('file'), async (req, res) => {
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

// 在本地开发时，需要一个根路由来提供index.html
if (process.env.VERCEL !== '1') {
    app.use(express.static(path.join(__dirname, 'public')));
    app.listen(port, () => {
        console.log(`服务器正在 http://localhost:${port} 上运行`);
    });
}

// 导出 app 供 Vercel 使用
module.exports = app;
