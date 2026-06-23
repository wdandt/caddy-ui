FROM oven/bun:alpine

WORKDIR /app

COPY package*.json ./

RUN bun install --production

COPY . .

# Auto-inject build timestamp to bust browser cache for static files
RUN sed -i -E "s/main\.js\?v=[0-9]+/main.js?v=$(date +%s)/g" public/index.html && \
    sed -i -E "s/style\.css\?v=[0-9]+/style.css?v=$(date +%s)/g" public/index.html

EXPOSE 3000

ENV PORT=3000
ENV NODE_ENV=production

CMD ["bun", "run", "server.js"]
