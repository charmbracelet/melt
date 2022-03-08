FROM gcr.io/distroless/static
COPY melt /usr/local/bin/melt
ENTRYPOINT [ "/usr/local/bin/melt" ]
