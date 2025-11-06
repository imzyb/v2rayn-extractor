// api/generators.js
const { URLSearchParams } = require('url');
const { Buffer } = require('buffer');

function generateShareLinks(nodes) {
    const results = [];

    for (const node of nodes) {
        let link = '';
        const type = (node.type || '').toLowerCase();
        const remarks = encodeURIComponent(node.name || 'N/A');
        const server = node.server;
        const port = node.port;

        // 基本验证：没有服务器地址或端口的节点无法生成链接
        if (!server || !port) continue;

        try {
            if (type === 'vless' && node.uuid) {
                const params = new URLSearchParams();
                if (node.network) params.set('type', node.network);
                if (node.tls) {
                    if (node['reality-opts'] && node['reality-opts']['public-key']) {
                        params.set('security', 'reality');
                        params.set('pbk', node['reality-opts']['public-key']);
                        if (node['reality-opts']['short-id']) params.set('sid', node['reality-opts']['short-id']);
                    } else {
                        params.set('security', 'tls');
                    }
                    if (node.servername || node.sni) params.set('sni', node.servername || node.sni);
                    if (node['skip-cert-verify']) params.set('allowInsecure', '1');
                    if (node.flow) params.set('flow', node.flow);
                }
                if (node['client-fingerprint']) params.set('fp', node['client-fingerprint']);
                if (node.network === 'ws' && node['ws-opts']) {
                    if (node['ws-opts'].path) params.set('path', node['ws-opts'].path);
                    if (node['ws-opts'].headers && node['ws-opts'].headers.Host) params.set('host', node['ws-opts'].headers.Host);
                }
                if (node.network === 'grpc' && node['grpc-opts'] && node['grpc-opts']['grpc-service-name']) {
                    params.set('serviceName', node['grpc-opts']['grpc-service-name']);
                }
                link = `vless://${node.uuid}@${server}:${port}?${params.toString()}#${remarks}`;

            } else if (type === 'vmess') {
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
                const creds = `${node.cipher || node.method}:${node.password}`;
                link = `ss://${Buffer.from(creds).toString('base64')}@${server}:${port}#${remarks}`;

            } else if (type === 'trojan' && node.password) {
                const params = new URLSearchParams();
                if (node.servername || node.sni) params.set('sni', node.servername || node.sni);
                if (node.network === 'ws') {
                     params.set('type', 'ws');
                     if (node['ws-opts']?.path) params.set('path', node['ws-opts'].path);
                     if (node['ws-opts']?.headers?.Host) params.set('host', node['ws-opts'].headers.Host);
                }
                link = `trojan://${encodeURIComponent(node.password)}@${server}:${port}?${params.toString()}#${remarks}`;

            } else if (type === 'hysteria2') {
                 const params = new URLSearchParams();
                 if (node.servername || node.sni) params.set('sni', node.servername || node.sni);
                 if (node['skip-cert-verify']) params.set('insecure', '1');
                 link = `hysteria2://${encodeURIComponent(node.auth || node.password || '')}@${server}:${port}?${params.toString()}#${remarks}`;
            }
        } catch (e) {
            console.error(`生成 ${node.name} 的链接时出错:`, e);
        }

        if (link) {
            // 返回结构化数据，供前端表格使用
            results.push({
                link: link,
                info: {
                    name: node.name || 'Unknown',
                    type: type,
                    server: server,
                    port: port
                }
            });
        }
    }
    return results;
}

module.exports = { generateShareLinks };
