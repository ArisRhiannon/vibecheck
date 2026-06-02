FROM node:20-slim
WORKDIR /app
RUN npm install @arisrhiannon/vibecheck
CMD ["npx", "vibecheck", "mcp"]

