# ResourceMonitor


This project is a **real-time server monitoring web application** designed as part of the CS 395 Fall 2024 course. The application allows users to view real-time metrics about server performance, system usage, and connected processes. This document outlines the project's features, architecture, and setup process.

## Project Features

### Functional Features
1. **Real-Time Monitoring:**
   - Monitors CPU, memory, and disk usage with dynamic ring charts.
   - Displays tasks, threads, running processes, and load averages.
   - Lists top processes, open ports, logged-in users, system logs, and last user activity dynamically.

2. **Interactive Web Interface:**
   - **Dark Mode Toggle:** A slider button allows users to switch between light and dark modes.
   - Responsive design ensures a smooth user experience across devices.

3. **Secure Access:**
   - A login page restricts access to authorized users.
   - Credentials are verified using hashed passwords stored as environment variables.

### Technical Features
1. **WebSocket Communication:**
   - Enables real-time updates by pushing server metrics and data directly to the client.

2. **Docker Integration:**
   - Docker ensures a consistent environment for the application and simplifies deployment.

3. **Customizable Interface:**
   - Users can sort table columns and adjust the number of displayed logs dynamically.

4. **System Compatibility:**
   - Cross-platform compatibility for Linux, macOS, and Windows servers.

---

## Architecture Overview

1. **Frontend:**
   - Built with **HTML, CSS, and JavaScript** to provide an interactive and visually appealing UI.
   - Features dynamic elements such as real-time ring charts and sortable tables.

2. **Backend:**
   - Powered by Python with **aiohttp** to manage WebSocket communication and serve static files.
   - Gathers system statistics using Python libraries such as **psutil** and sends updates via WebSocket.

3. **Dockerized Setup:**
   - Uses Docker to encapsulate the application, ensuring a consistent runtime environment.

---

## Setup Instructions

### Prerequisites
- **Docker** and **Docker Compose** must be installed.
- Basic understanding of running Docker containers.

### Build and Run the Application
1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-folder>
   ```

2. Build the Docker image:
   ```bash
   docker build -t server-monitor .
   docker build -t image_mert .
   ```


### Deploy on Class Server
1. Check your Linux user ID by running the following command:
   ```bash
   id -u
   ```
   Example output: `1001`.

2. Build and run the Docker container with the correct port mapping:
   ```bash
   docker build -t server-monitor .
   docker run -p 1001:8765 server-monitor

      docker run -d   --name mert   -p 1017:8765   --pid=host   -v /var/run/utmp:/var/run/utmp:ro   -v /var/log/wtmp:/var/log/wtmp:ro   -v /var/log/syslog:/var/log/syslog:ro   -v /proc:/host_proc:ro   --restart=always   image_mert
   ```


3. Access the application on the class server:
   - Open your browser and navigate to `https://cs395.org/1017/monitor`.

4. WebSocket endpoint:
   - WebSocket communication occurs at `https://cs395.org/1017/ws`.

---

## Application Features in Detail


### Monitoring Dashboard
After the user inputs the password and submits it, the webpage monitors the statistics.
- URL: `/monitor`
- Displays:
  - **System Resources:** CPU, memory, and disk usage.
  - **System Overview:** Tasks, threads, running processes, and load averages.
  - **System Info:** Uptime and battery status.
  - **IP Addresses:** Local and external IPs.

### WebSocket Data Streams
- Dynamically updates tables and metrics every few seconds.
- Ensures low latency and smooth user experience.

### Dark Mode Toggle
- A slider button in the top-right corner allows switching between light and dark themes.
- Dark mode ensures all text and elements remain legible.

### Process Management
- Allows users to kill processes by entering the process ID (PID).
- Displays the status of the action (success/error).

### Dynamic Tables
- **Tabs:**
  - Top Processes
  - Port Data
  - Logged-in Users
  - System Logs
  - Last Users
- Tables are sortable and adjust dynamically based on user input.

---

## Docker Features

1. **Encapsulation:**
   - The application is fully encapsulated within a Docker container.
   - Includes all dependencies and libraries needed to run the application.

2. **Port Mapping:**
   - Locally: Maps the container's port `8765` to the host's `8765`.
   - Class Server: Dynamically maps the container's port `8765` to your user ID (e.g., `1001`).

3. **File Structure:**
   - **`app/cert`**: Contains SSL certificates for HTTPS.
   - **`src`**: Contains the server Python script.
   - **`monitor.html`**: Frontend files served by the application.

4. **Build Configuration:**
   - Dockerfile optimizations, including using a lightweight Python image and caching dependencies.

---

## File Structure
```plaintext
project-folder/
├── cert/
│   ├── localhost.crt       # SSL certificate
│   ├── localhost.key       # SSL private key
├── src/
│   ├── hello.html          # Login page
│   ├── monitor.html        # Monitoring dashboard
│   └── server.py           # Main Python application
├── Dockerfile              # Docker configuration
├── docker-compose.yml      # Docker Compose file (optional)
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```
