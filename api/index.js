// api/index.js
const express = require('express');
const multer = require('multer');
const axios = require('axios');
const path = require('path');
const { Buffer } = require('buffer');

// 引入新模块
const { extractNodesFromYamlContent } = require('./parsers');
const { generateShareLinks } = require('./generators');

const app = express();
const port = 3000;
const upload = multer({ storage: multer.memoryStorage() });

app.use(express.json()); // 解析 JSON 请求体

app.post('/api/extract', upload.single('file'), async (req, res) => {
    const { inputType, url, json_input } = req.body;
    let rawContent = '';

    try {
        // 1. 获取原始内容
        if (inputType === 'url') {
            if (!url) return res.status(400).json({ error: '未提供URL' });
            const response = await axios.get(url, {
                headers: { 
                    'User-Agent': 'ClashForAndroid/2.5.12',
                    'Accept': '*/*'
                },
                responseType: 'arraybuffer',
                timeout: 15000
            });
            rawContent = response.data.toString('utf8');
        } else if (inputType === 'file') {
            if (!req.file) return res.status(400).json({ error: '未提供文件' });
            rawContent = req.file.buffer.toString('utf8');
        } else if (inputType === 'json') {
            rawContent = json_input || '';
        }

        // 2. 解析节点
        let nodes = extractNodesFromYamlContent(rawContent);
        
        // 如果直接解析失败，尝试 Base64 解码后再解析
        if (nodes.length === 0 && rawContent) {
            try {
                const decoded = Buffer.from(rawContent.trim(), 'base64').toString('utf8');
                nodes = extractNodesFromYamlContent(decoded);
            } catch (_) {}
        }

        if (nodes.length === 0) {
            return res.status(400).json({ 
                error: '未能找到有效节点。请确认订阅返回的是 Clash/Sing-box 配置或标准节点列表。' 
            });
        }

        // 3. 生成链接和结构化数据
        const results = generateShareLinks(nodes);
        if (results.length === 0) {
             return res.status(400).json({ error: '节点存在，但无法生成有效链接（可能缺少必要字段）。' });
        }

        // 4. 构造统计信息
        const protocolCounts = results.reduce((acc, item) => {
            const type = item.info.type;
            acc[type] = (acc[type] || 0) + 1;
            return acc;
        }, {});
        const countDetails = Object.entries(protocolCounts)
            .map(([k, v]) => `${k.toUpperCase()}: ${v}`)
            .join(', ');

        // 5. 返回 JSON 响应
        res.json({
            success: true,
            message: `成功提取 ${results.length} 个节点`,
            summary: `分类统计: ${countDetails}`,
            // 方便前端 "复制全部"
            all_links: results.map(r => r.link).join('\n'),
            // 方便前端渲染表格
            nodes: results
        });

    } catch (error) {
        console.error('API Error:', error.message);
        res.status(500).json({ error: `服务器内部错误: ${error.message}` });
    }
});

// 本地开发静态文件服务
if (process.env.VERCEL !== '1') {
    app.use(express.static(path.join(__dirname, '../public')));
    app.listen(port, () => console.log(`Local server running on http://localhost:${port}`));
}

module.exports = app;
