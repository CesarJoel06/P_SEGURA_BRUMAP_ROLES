FROM node:20-bullseye-slim

# Entorno de producción dentro del contenedor
ENV NODE_ENV=production

# Directorio de trabajo
WORKDIR /app

# Copiamos sólo archivos necesarios para instalar dependencias
# Los patrones con * permiten usar package-lock.json y .npmrc si existen
COPY package.json package-lock.json* .npmrc* ./

# Instalamos dependencias sin las de desarrollo
# Si falla la opción con --omit=dev (por versión de npm), hace un npm install normal
RUN npm install --omit=dev || npm install

# Copiamos el resto del código de la aplicación
COPY . .

# Asignamos la propiedad de la app al usuario 'node' que ya existe en la imagen oficial
RUN chown -R node:node /app

# A partir de aquí, dejamos de usar root y corremos como usuario no privilegiado
USER node

# Puerto de la aplicación
EXPOSE 3000

# Comando de arranque
CMD ["node", "server.js"]
