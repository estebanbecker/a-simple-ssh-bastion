FROM python:3.13-rc-bookworm
WORKDIR /app

# Install the application dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY test_rsa.key ./

# Copy in the source code
COPY src ./src
EXPOSE 42345

CMD ["python", "src/main.py"]