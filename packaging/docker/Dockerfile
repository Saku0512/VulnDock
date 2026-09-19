FROM ubuntu:25.10@sha256:7cc5e35f6567ee8c66d2abb4aab0fd866669e6207c237c3a8f0947a5c7f17092

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
