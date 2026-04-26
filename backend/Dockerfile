FROM node:20-slim

WORKDIR /app

# Evitar prompts
ENV DEBIAN_FRONTEND=noninteractive

# Dependencias del sistema
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    libimobiledevice6 \
    libimobiledevice-utils \
    ideviceinstaller \
    ifuse \
    usbmuxd \
    usbutils \
    make \
    g++ \
    git \
    postgresql-client \
    openjdk-17-jre-headless \
    wget \
    unzip \
    bash \
    android-tools-adb \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# APKTool
RUN wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool && \
    wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.12.1.jar -O /usr/local/bin/apktool.jar && \
    chmod +x /usr/local/bin/apktool

# JADX
RUN wget https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip -O /tmp/jadx.zip && \
    unzip /tmp/jadx.zip -d /opt/jadx && \
    ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx && \
    rm /tmp/jadx.zip 

# tools and pip

COPY tools ./
RUN pip install -r requirements.txt --break-system-packages

COPY rules ./
COPY package*.json ./
COPY tsconfig.json ./

RUN npm install

COPY . .

RUN mkdir -p uploads analysis_results logs analysis_results/bundles

EXPOSE 3001

CMD ["npm", "run", "dev"]
