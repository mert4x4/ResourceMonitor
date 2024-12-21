# Base Image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy requirements file first for dependency caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code and other required files
COPY src ./src
COPY cert ./cert

# Set environment variables for credentials
ENV USERNAME=admin
ENV PASSWORD_HASH=f307d19df6386be176ac13771b02c89ce71c2cb551ead8a6069931c6a9cb1215

# Expose the application port
EXPOSE 8765

# Run the application
CMD ["python", "src/server.py"]
