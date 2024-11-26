FROM python:3.13-slim-bookworm
WORKDIR /app

# Install the application dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Create the user_keys directory
RUN mkdir -p user_keys
RUN mkdir -p config
RUN mkdir -p logs
RUN mkdir -p server_public_keys

# Copy in the source code
COPY src ./src
EXPOSE 2222

CMD ["python", "src/main.py"]