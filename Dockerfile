# 1. 使用一个官方的、轻量的 Node.js 20 镜像作为基础
FROM node:20-alpine

# 2. 在容器内部创建一个工作目录
WORKDIR /app

# 3. 复制 package.json 和 package-lock.json (如果存在)
#    这样做可以利用 Docker 的缓存机制，如果依赖没变，就不用重新安装
COPY package*.json ./

# 4. 安装生产环境需要的依赖
RUN npm install --production

# 5. 将我们项目的所有文件复制到容器的工作目录中
COPY . .

# 6. 向外界声明容器将使用 3000 端口
EXPOSE 3000

# 7. 定义容器启动时要执行的命令
CMD [ "node", "server.js" ]