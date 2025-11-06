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

function normalizeNode(node) {
    // 浅拷贝，避免修改原对象
    const n = { ...node };

    // 1. 统一端口字段
    if (!n.port && n.server_port) n.port = n.server_port;

    // 2. 适配 Sing-box 的 TLS 嵌套结构
    if (n.tls && typeof n.tls === 'object') {
        // 提取 TLS 常用字段到顶层
        if (n.tls.server_name) n.servername = n.tls.server_name;
        if (n.tls.alpn) n.alpn = n.tls.alpn;
        if (n.tls.insecure) n['skip-cert-verify'] = true;
        
        // 适配 Reality
        if (n.tls.reality && n.tls.reality.enabled) {
            n['reality-opts'] = {
                'public-key': n.tls.reality.public_key,
                'short-id': n.tls.reality.short_id
            };
        }
        // 确保 tls 标记为 true，如果它在 sing-box 中被启用
        n.tls = n.tls.enabled === true;
    }

    // 3. 适配 Sing-box 的 Transport 嵌套结构
    if (n.transport && typeof n.transport === 'object') {
        n.network = n.transport.type;
        // WS 配置
        if (n.network === 'ws') {
            n['ws-opts'] = {
                path: n.transport.path,
                headers: n.transport.headers
            };
        }
        // gRPC 配置
        if (n.network === 'grpc') {
            n['grpc-opts'] = {
                'grpc-service-name': n.transport.service_name
            };
        }
    }

    // 4. 统一别名/备注字段 (Sing-box 使用 tag)
    if (!n.name && n.tag) n.name = n.tag;

    return n;
}

// --- 增强版提取函数 ---
function extractNodesFromYamlContent(content) {
    try {
        const data = yaml.load(content);
        let rawNodes = [];

        // 情况1: 标准 Clash 格式 { proxies: [...] }
        if (data && data.proxies && Array.isArray(data.proxies)) {
            rawNodes = data.proxies;
        }
        // 情况2: Sing-box 格式 { outbounds: [...] }
        else if (data && data.outbounds && Array.isArray(data.outbounds)) {
            // 过滤掉非代理类型的 outbound
            rawNodes = data.outbounds.filter(node => {
                const type = (node.type || '').toLowerCase();
                return type && 
                       type !== 'selector' && 
                       type !== 'urltest' && 
                       type !== 'direct' && 
                       type !== 'block' && 
                       type !== 'dns';
            });
        }
        // 情况3: 直接返回了数组 [...]
        else if (Array.isArray(data)) {
            rawNodes = data;
        }
        // 情况4: 其他可能的变种 (Meta等)
        else if (data && typeof data === 'object') {
             // 最后的尝试：寻找可能是节点的数组字段
             const possibleKeys = ['nodes'];
             for (const key of possibleKeys) {
                 if (data[key] && Array.isArray(data[key])) {
                     rawNodes = data[key];
                     break;
                 }
             }
        }

        // 对所有提取出的节点进行标准化处理
        return rawNodes.map(normalizeNode);

    } catch (e) {
        console.error("解析配置内容失败:", e);
        return [];
    }
}

function generateShareLinks(nodes) {
    const shareLinks = [];
    for (const node of nodes) {
        let link = '';
        try {
            const type = (node.type || '').toLowerCase();
            // 使用标准化后的 name (原 tag)
            const remarks = encodeURIComponent(node.name || 'N/A');
            const server = node.server;
            const port = node.port;

            if (!server || !port) continue; // 跳过不完整的节点

            if (type === 'vless' && node.uuid) {
                const params = new URLSearchParams();
                if (node.network) params.set('type', node.network);
                // TLS / Reality
                if (node.tls) {
                    if (node['reality-opts'] && node['reality-opts']['public-key']) {
                        params.set('security', 'reality');
                        params.set('pbk', node['reality-opts']['public-key']);
                        if (node['reality-opts']['short-id']) params.set('sid', node['reality-opts']['short-id']);
                    } else {
                        params.set('security', 'tls');
                    }
                    // 通用 TLS 参数
                    if (node.servername || node.sni) params.set('sni', node.servername || node.sni);
                    if (node.alpn && Array.isArray(node.alpn)) params.set('alpn', node.alpn.join(','));
                    else if (typeof node.alpn === 'string') params.set('alpn', node.alpn);
                    if (node['skip-cert-verify']) params.set('allowInsecure', '1');
                }
                
                if (node.flow) params.set('flow', node.flow);
                if (node['client-fingerprint']) params.set('fp', node['client-fingerprint']);
                
                // Transport 参数
                if (node.network === 'ws' && node['ws-opts']) {
                    if (node['ws-opts'].path) params.set('path', node['ws-opts'].path);
                    if (node['ws-opts'].headers && node['ws-opts'].headers.Host) params.set('host', node['ws-opts'].headers.Host);
                }
                if (node.network === 'grpc' && node['grpc-opts']) {
                    if (node['grpc-opts']['grpc-service-name']) params.set('serviceName', node['grpc-opts']['grpc-service-name']);
                }
                link = `vless://${node.uuid}@${server}:${port}?${params.toString()}#${remarks}`;

            } else if (type === 'vmess') {
// VMess 处理逻辑... (此处略微精简，逻辑同前)
                 const vmessConfig = {
                    v: '2', ps: decodeURIComponent(remarks), add: server, port: port, id: node.uuid,
                    aid: node.alterId || 0, scy: node.cipher || 'auto', net: node.network || 'tcp',
                    type: 'none', 
                    host: node['ws-opts']?.headers?.Host || node.servername || '', 
                    path: node['ws-opts']?.path || node['http-opts']?.path?.[0] || '',
                    tls: node.tls ? 'tls' : '',
                    sni: node.servername || node.sni || ''
                };
                link = `vmess://${Buffer.from(JSON.stringify(vmessConfig)).toString('base64')}`;

            } else if ((type === 'ss' || type === 'shadowsocks') && (node.cipher || node.method) && node.password) {
                const cipher = node.cipher || node.method;
                const credentials = `${cipher}:${node.password}`;
                link = `ss://${Buffer.from(credentials).toString('base64')}@${server}:${port}#${remarks}`;

            } else if (type === 'trojan' && node.password) {
                const params = new URLSearchParams();
                if (node.servername || node.sni) params.set('sni', node.servername || node.sni);
                if (node['skip-cert-verify']) params.set('allowInsecure', '1');
                if (node.network === 'ws') {
                     params.set('type', 'ws');
                     if (node['ws-opts']?.path) params.set('path', node['ws-opts'].path);
                     if (node['ws-opts']?.headers?.Host) params.set('host', node['ws-opts'].headers.Host);
                }
                link = `trojan://${encodeURIComponent(node.password)}@${server}:${port}?${params.toString()}#${remarks}`;

            } else if (type === 'hysteria2') {
                 const auth = node.auth || node.password || '';
                 const params = new URLSearchParams();
                 if (node.servername || node.sni) params.set('sni', node.servername || node.sni);
                 if (node['skip-cert-verify']) params.set('insecure', '1');
                 if (node.obfs && node.obfs.type === 'salamander') {
                      params.set('obfs', 'salamander');
                      if (node.obfs.password) params.set('obfs-password', node.obfs.password);
                 }
                 link = `hysteria2://${encodeURIComponent(auth)}@${server}:${port}?${params.toString()}#${remarks}`;
            }

            if (link) shareLinks.push(link);
        } catch (e) { 
            // console.error(`生成链接失败:`, e); 
        }
    }
    return shareLinks;
}

// --- API 路由 ---

app.post('/api/extract', upload.single('file'), async (req, res) => {
    const { inputType, url, json_input } = req.body;
    let nodes = [];

    try {
        let rawContent = '';
        if (inputType === 'url') {
            if (!url) return res.status(400).send('错误：未提供URL。');
            // 模拟常用客户端 UA
            const response = await axios.get(url, { 
                headers: { 
                    'User-Agent': 'ClashForAndroid/2.5.12', // 尝试使用 CFA 的 UA
                    'Accept': '*/*'
                },
                responseType: 'arraybuffer',
                timeout: 20000
            });
            rawContent = response.data.toString('utf8');
            
            // 尝试解析，如果失败尝试 Base64 解码
            nodes = extractNodesFromYamlContent(rawContent);
            if (nodes.length === 0) {
                try {
                    nodes = extractNodesFromYamlContent(Buffer.from(rawContent, 'base64').toString('utf8'));
                } catch (_) {}
            }

        } else if (inputType === 'file') {
            if (!req.file) return res.status(400).send('错误：未提供文件。');
            rawContent = req.file.buffer.toString('utf8');
            nodes = extractNodesFromYamlContent(rawContent);

        } else if (inputType === 'json') {
            // 对原始 JSON 输入也进行同样的提取逻辑
            nodes = extractNodesFromYamlContent(json_input);
        }

        // 过滤有效节点
        nodes = nodes.filter(n => n && n.type && n.server && n.port);

        if (nodes.length === 0) {
             // 如果还是没有，尝试作为纯 Base64 文本处理（兜底）
             try {
                 const decoded = Buffer.from(rawContent.trim(), 'base64').toString('utf8');
                 if (decoded.includes('vmess://') || decoded.includes('vless://') || decoded.includes('ss://')) {
                     return res.status(200).send(decoded + '\n\n---\n成功解码 Base64 订阅内容。');
                 }
             } catch (_) {}

            return res.status(400).send('未能找到有效节点。请确认订阅链接返回的是 Clash、Sing-box 配置，或标准的节点列表。');
        }

        const shareLinks = generateShareLinks(nodes);
        const summary = `\n\n---\n成功提取 ${shareLinks.length} 个节点。`;
        
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.status(200).send(shareLinks.join('\n') + summary);

    } catch (error) {
        res.status(500).send(`处理出错: ${error.message}`);
    }
});

if (process.env.VERCEL !== '1') {
    app.use(express.static(path.join(__dirname, '../public')));
    app.listen(port, () => {
        console.log(`Listening on http://localhost:${port}`);
    });
}

module.exports = app;
