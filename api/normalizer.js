// api/normalizer.js
function normalizeNode(node) {
    const n = { ...node };

    // 1. 统一基础字段
    if (!n.port && n.server_port) n.port = n.server_port;
    // 统一名称字段，Sing-box 使用 tag，Clash 使用 name
    if (!n.name && n.tag) n.name = n.tag;
    if (!n.name) n.name = 'unnamed-node';

    // 2. 适配 Sing-box 的 TLS 嵌套结构
    if (n.tls && typeof n.tls === 'object') {
        if (n.tls.server_name) n.servername = n.tls.server_name;
        if (n.tls.alpn) n.alpn = n.tls.alpn;
        if (n.tls.insecure) n['skip-cert-verify'] = true;
        
        if (n.tls.reality && n.tls.reality.enabled) {
            n['reality-opts'] = {
                'public-key': n.tls.reality.public_key,
                'short-id': n.tls.reality.short_id
            };
        }
        // 确保 tls 标记为布尔值 true，以便后续生成器识别
        n.tls = n.tls.enabled !== false; 
    }

    // 3. 适配 Sing-box 的 Transport 嵌套结构
    if (n.transport && typeof n.transport === 'object') {
        n.network = n.transport.type;
        if (n.network === 'ws') {
            n['ws-opts'] = {
                path: n.transport.path,
                headers: n.transport.headers
            };
        }
        if (n.network === 'grpc') {
            n['grpc-opts'] = {
                'grpc-service-name': n.transport.service_name
            };
        }
    }

    return n;
}

module.exports = normalizeNode;
