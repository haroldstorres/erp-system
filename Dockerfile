FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY . .
# Cloud Run injects PORT; server.js already reads process.env.PORT
CMD ["node", "server.js"]
