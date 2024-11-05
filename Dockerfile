FROM python:3.14-rc-bookworm
WORKDIR /app

# Install the application dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy in the source code
COPY src ./src
EXPOSE 22

CMD ["python", "src/main.py"]