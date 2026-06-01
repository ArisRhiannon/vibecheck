FROM node:20-slim
RUN npm install -g @arisrhiannon/vibecheck@0.1.0
ENTRYPOINT ["vibecheck", "mcp"]
