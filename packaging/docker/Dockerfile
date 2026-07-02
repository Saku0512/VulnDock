FROM ubuntu:26.04@sha256:53958ec7b67c2c9355df922dd08dbf0360611f8c3cdb656875e81873db9ffdba

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    libgtk-3-0 \
    libwebkit2gtk-4.1-0 \
    xdg-utils \
  && rm -rf /var/lib/apt/lists/*

COPY VulnDock /usr/local/bin/VulnDock
COPY vulndock.desktop /usr/share/applications/vulndock.desktop
COPY vulndock.png /usr/share/icons/hicolor/256x256/apps/vulndock.png

RUN chmod 0755 /usr/local/bin/VulnDock

ENTRYPOINT ["/usr/local/bin/VulnDock"]
