# Build from the parent directory (Faultline depends on the sibling RetrievalLab package):
#   docker build -f Faultline/Dockerfile -t faultline .
#   docker run -p 8200:8200 -e FAULTLINE_API_KEYS=viewkey:viewer,runkey:investigator,adminkey:approver faultline
FROM python:3.11-slim
WORKDIR /app
COPY RetrievalLab /app/RetrievalLab
COPY Faultline /app/Faultline
RUN pip install --no-cache-dir /app/RetrievalLab "mcp<2" /app/Faultline
ENV FAULTLINE_DB=/app/data/faultline.db
EXPOSE 8200
CMD ["faultline", "serve", "--host", "0.0.0.0", "--port", "8200"]
