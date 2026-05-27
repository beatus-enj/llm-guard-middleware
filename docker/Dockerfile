FROM python:3.12-slim

WORKDIR /app


# 依赖安装（分层缓存）
COPY requirements.txt .
RUN pip install --no-cache-dir \
    fastapi uvicorn==0.47.0 httpx python-multipart \
    pyyaml python-dotenv watchdog

COPY app/ ./app/
COPY config/ ./config/
COPY run.py .
COPY ./llm-guard-rust/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# 非 root 用户
RUN useradd -r -u 1001 guard && chown -R guard:guard /app
USER guard

EXPOSE 8000

# CMD ["python3", "run.py"]
# 无需设置 PATH，直接使用 Python 模块方式运行
CMD ["python3", "-m", "uvicorn", "run:app", "--host", "0.0.0.0", "--port", "8000"]
