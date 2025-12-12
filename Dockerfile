# Imagen base de Node con Debian (compatibles sqlite3, pdfkit, etc.)
FROM node:20-bookworm-slim

# Directorio de trabajo dentro del contenedor
WORKDIR /usr/src/app

# (Opcional pero recomendable) Paquetes para compilar dependencias nativas
# como sqlite3 si no hay binarios precompilados
RUN apt-get update && \
    apt-get install -y python3 build-essential && \
    rm -rf /var/lib/apt/lists/*

# Copiar solo package.json/package-lock primero para aprovechar cache
COPY package*.json ./

# Instalar dependencias en modo producción
RUN npm ci --omit=dev || npm install --omit=dev

# Copiar el resto del código de la app
COPY . .

# Crear carpeta de datos y dar permisos al usuario "node"
RUN mkdir -p Data data && chown -R node:node /usr/src/app

# Usar usuario no root
USER node

# Variables de entorno por defecto (se pueden sobreescribir en docker run)
ENV NODE_ENV=production

# Puerto donde escucha tu app
EXPOSE 3000

# Comando de inicio
CMD ["node", "server.js"]
