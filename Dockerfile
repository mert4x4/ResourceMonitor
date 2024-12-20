# Use Python 3.12 as the base image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file to the container
COPY requirements.txt .

# Install the dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project to the working directory in the container
COPY . .

# Expose the port used by the application (8765)
EXPOSE 8765

# Run the application
CMD ["python", "server.py"]
