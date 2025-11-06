// api/parsers.js
const yaml = require('js-yaml');
const normalizeNode = require('./normalizer');

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
            // 过滤掉 Sing-box 中的非代理节点
            rawNodes = data.outbounds.filter(node => {
                const type = (node.type || '').toLowerCase();
                return type && !['selector', 'urltest', 'direct', 'block', 'dns'].includes(type);
            });
        }
        // 情况3: 直接返回了数组 [...]
        else if (Array.isArray(data)) {
            rawNodes = data;
        }
        // 情况4: 尝试查找其他可能的节点数组字段 (如 Meta 的 nodes)
        else if (data && typeof data === 'object') {
             const possibleKeys = ['nodes'];
             for (const key of possibleKeys) {
                 if (data[key] && Array.isArray(data[key])) {
                     rawNodes = data[key];
                     break;
                 }
             }
        }

        // 提取完成后，立即进行标准化
        return rawNodes.map(normalizeNode);

    } catch (e) {
        // console.warn("YAML/JSON 解析失败，可能不是标准格式文本");
        return [];
    }
}

module.exports = { extractNodesFromYamlContent };
