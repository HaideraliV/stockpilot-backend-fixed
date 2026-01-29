FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
# Railway sometimes tries to execute "railway" as the start command; provide a shim.
RUN printf '#!/bin/sh\nexec npm start\n' > /usr/local/bin/railway && chmod +x /usr/local/bin/railway
EXPOSE 4000
ENTRYPOINT ["/usr/local/bin/railway"]
