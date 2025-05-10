FROM node:18-alpine AS frontend-build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM python:3.10-slim AS backend-build

WORKDIR /app/backend

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./

FROM node:18-alpine AS runner

WORKDIR /app

# Copy built NextJS application
COPY --from=frontend-build /app/.next ./.next
COPY --from=frontend-build /app/node_modules ./node_modules
COPY --from=frontend-build /app/package.json ./package.json
COPY --from=frontend-build /app/public ./public

# Copy Python backend
COPY --from=backend-build /app/backend ./backend
# Copy the Python runtime
COPY --from=backend-build /usr/local/lib/python3.10 /usr/local/lib/python3.10
COPY --from=backend-build /usr/local/bin/python /usr/local/bin/python
COPY --from=backend-build /usr/local/bin/pip /usr/local/bin/pip

# Install PM2 for process management
RUN npm install -g pm2

# Copy ecosystem file for PM2
COPY ecosystem.config.js ./

# Expose ports for frontend and backend
EXPOSE 3000
EXPOSE 8000

# Start both services with PM2
CMD ["pm2-runtime", "start", "ecosystem.config.js"]
