# Use Python 3.12 as the base image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file to the container
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project into the container
COPY . .

# Change to the directory containing server.py
WORKDIR /app/src

# Expose the port used by the application
EXPOSE 8765

# Start the application
CMD ["python", "server.py"]
