import asyncio
import json
import pathlib
import ssl
import psutil
from aiohttp import web
import time
from datetime import timedelta
import socket
import requests
import os
import subprocess

async def get_logged_in_users():
    users = []
    try:
        for user in psutil.users():
            users.append({
                "name": user.name,
                "terminal": user.terminal or "N/A",
                "host": user.host or "Local",
                "started": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(user.started))
            })
    except Exception as e:
        print(f"Error getting logged-in users...: {e}")
    return users


async def get_ip_addresses():
    result = {"local_ipv4": None, "external_ip": None}

    #get ipv4
    try:
        hostname = socket.gethostname()
        result["local_ipv4"] = socket.gethostbyname(hostname)
    except Exception as e:
        result["local_ipv4"] = f"Error: {e}"

    #get external ip adress
    try:
        response = requests.get("https://api.ipify.org?format=json")
        response.raise_for_status()
        result["external_ip"] = response.json()["ip"]
    except Exception as e:
        result["external_ip"] = f"Error: {e}"

    return result


async def get_process_ports():
    process_ports = []

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            connections = proc.connections(kind='inet')
            for conn in connections:
                if conn.laddr:
                    if conn.raddr:
                        remote_address = f"{conn.raddr.ip}:{conn.raddr.port}"
                    else:
                        remote_address = "N/A"

                    if conn.type == socket.SOCK_STREAM:
                        protocol = 'TCP'
                    else:
                        protocol = 'UDP'

                    process_ports.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_address': remote_address,
                        'status': conn.status,
                        'protocol': protocol
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return process_ports


async def get_system_overview():
    overview = {}

    all_processes = list(psutil.process_iter())
    overview["tasks"] = len(all_processes)

    total_threads = 0
    for proc in all_processes:
        if hasattr(proc, "num_threads"):
            total_threads += proc.num_threads()
    overview["threads"] = total_threads

    running_processes = []
    for proc in all_processes:
        if proc.status() == psutil.STATUS_RUNNING:
            running_processes.append(proc)
    overview["running"] = len(running_processes)

    load_avg = psutil.getloadavg()
    overview["load_average"] = load_avg

    boot_time = psutil.boot_time()
    current_time = time.time()
    uptime_seconds = int(current_time - boot_time)
    overview["uptime"] = str(timedelta(seconds=uptime_seconds))

    battery = psutil.sensors_battery()
    if battery is not None:
        overview["battery"] = {
            "percent": battery.percent,
            "power_plugged": battery.power_plugged
        }
    else:
        overview["battery"] = "No battery information available"

    return overview



async def get_top_processes():
    processes = []

    for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'username', 'cmdline', 'cpu_percent', 'memory_info', 'status', 'create_time', 'num_threads', 'nice']):
        try:
            proc.cpu_percent(interval=0)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            continue

    time.sleep(1)

    for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent', 'username', 'cmdline', 'memory_info', 'status', 'create_time', 'num_threads', 'nice']):
        try:
            proc_info = proc.info
            memory_info = proc.memory_info()

            if memory_info is not None:
                proc_info['memory_mb'] = memory_info.rss / (1024 ** 2)
                proc_info['virt_memory_mb'] = memory_info.vms / (1024 ** 2)
                if hasattr(memory_info, 'shared'):
                    proc_info['shr_memory_mb'] = memory_info.shared / (1024 ** 2)
                else:
                    proc_info['shr_memory_mb'] = 0

            if hasattr(proc, 'nice'):
                proc_info['priority'] = proc.nice()

            if 'status' in proc_info and proc_info['status'] is None:
                proc_info['status'] = 'Unknown'

            if proc_info.get('cmdline'):
                proc_info['command'] = " ".join(proc_info['cmdline'])
            else:
                proc_info['command'] = 'Unknown'

            if 'create_time' in proc_info and proc_info['create_time']:
                proc_info['uptime'] = time.strftime("%H:%M:%S", time.gmtime(time.time() - proc_info['create_time']))
            else:
                proc_info['uptime'] = 'Unknown'

            if proc_info['memory_percent'] is not None and proc_info['cpu_percent'] is not None:
                processes.append(proc_info)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            continue

    top_cpu_processes = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:10]

    return top_cpu_processes



async def hello(request):
    text = "Hello"
    return web.Response(text=text)


async def monitor(request):
    path = pathlib.Path(__file__).parents[0].joinpath("monitor.html")
    print(f"Serving {path}")
    return web.FileResponse(path)


async def get_system_stats():
    """Collect system statistics."""
    stats = {
        "cpu": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory()._asdict(),
        "disk": psutil.disk_usage("/")._asdict(),
        "load_avg": psutil.getloadavg(),
    }
    return stats


async def get_system_logs(lines=50):
    try:
        current_os = os.uname().sysname

        if current_os == "Darwin":
            log_file = "/var/log/system.log"
        elif current_os == "Linux":
            log_file = "/var/log/syslog"
        else:
            return [f"Unsupported OS: {current_os}"]

        process = await asyncio.create_subprocess_exec(
            "tail", "-n", str(lines), log_file,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            return stdout.decode().splitlines()
        else:
            return [f"Error fetching logs: {stderr.decode().strip()}"]
    except Exception as e:
        return [f"Error occurred while fetching logs: {e}"]


async def get_last_user_logs(count=10):
    try:
        process = await asyncio.create_subprocess_exec(
            "last", "-n", str(count),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            logs = stdout.decode().strip().split("\n")
            return logs
        else:
            return [f"Error fetching logs: {stderr.decode().strip()}"]
    except Exception as e:
        return [f"Error occurred while fetching logs: {e}"]




async def send_stats(request):
    print("Client connected")
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    try:
        async for msg in ws:
            if msg.type == web.WSMsgType.text:
                print("message:" + msg.data);
                if msg.data.startswith("logs-"):
                    try:
                        lines = int(msg.data.split("-")[1])
                    except (IndexError, ValueError):
                        lines = 50 
                    data = await get_system_logs(lines=lines)
                    response = ["logs", data]
                elif msg.data.startswith("last_users-"):
                    try:
                        count = int(msg.data.split("-")[1])
                    except (IndexError, ValueError):
                        count = 10
                    data = await get_last_user_logs(count=count)
                    response = ["last_users", data]
                elif msg.data == "stats":
                    data = await get_system_stats()
                    response = ["stats", data]
                elif msg.data == "top_processes":
                    data = await get_top_processes()
                    response = ["top_processes", data]
                elif msg.data == "system_overview":
                    data = await get_system_overview()
                    response = ["system_overview", data]
                elif msg.data == "ports":
                    data = await get_process_ports()
                    response = ["port_data", data]
                elif msg.data == "ip_addresses":
                    data = await get_ip_addresses()
                    response = ["ip_addresses", data]
                elif msg.data == "users":
                    data = await get_logged_in_users()
                    response = ["users", data]
                else:
                    response = ["error", "Invalid request"]
                await ws.send_str(json.dumps(response, default=str))
            elif msg.type == web.WSMsgType.binary:
                continue
            elif msg.type == web.WSMsgType.close:
                print("Client closed connection")
                break
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        print("Connection closed")
    return ws


def create_ssl_context():
    """Create SSL context for secure WebSocket connection."""
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_file = pathlib.Path(__file__).parents[1].joinpath("cert/localhost.crt")
    key_file = pathlib.Path(__file__).parents[1].joinpath("cert/localhost.key")
    ssl_context.load_cert_chain(cert_file, key_file)
    return ssl_context


def run():
    """Start WebSocket server."""
    ssl_context = create_ssl_context()
    app = web.Application()
    app.add_routes(
        [
            web.get("/ws", send_stats),
            web.get("/monitor", monitor),
            web.get("/hello", hello),
        ]
    )
    web.run_app(app, port=8765, ssl_context=ssl_context)


if __name__ == "__main__":
    print("Server started at wss://localhost:8765")
    run()
