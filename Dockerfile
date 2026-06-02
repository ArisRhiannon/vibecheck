FROM node:20-slim
RUN npm install -g @arisrhiannon/vibecheck
ENTRYPOINT ["vibecheck", "mcp"]
