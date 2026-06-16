FROM oven/bun:alpine

WORKDIR /app

COPY package*.json ./

RUN bun install --production

COPY . .

EXPOSE 3000

ENV PORT=3000
ENV NODE_ENV=production

CMD ["bun", "run", "server.js"]
