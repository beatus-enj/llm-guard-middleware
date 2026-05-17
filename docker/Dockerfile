FROM python:3.12-slim

WORKDIR /app

# 依赖安装（分层缓存）
COPY requirements.txt .
RUN pip install --no-cache-dir flask requests pyyaml python-dotenv

COPY app/ ./app/
COPY config/ ./config/
COPY run.py .

# 非 root 用户
RUN useradd -r -u 1001 guard && chown -R guard:guard /app
USER guard

EXPOSE 8000

CMD ["python3", "run.py"]
