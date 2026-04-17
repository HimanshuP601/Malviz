import asyncio
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn
import os

from threat_engine import analyze_processes, get_all_network_packets, get_process_simulation_data
from database import init_db, log_threat, get_history
from inspector import analyze_process_deep, extract_strings, generate_minidump

app = FastAPI(title="Malviz")

# Initialize DB on startup
init_db()

# Serve static files
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def read_index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.get("/api/history")
async def read_history():
    return get_history()

@app.get("/api/inspect/{pid}")
async def inspect_pid(pid: int):
    return analyze_process_deep(pid)

@app.get("/api/network")
async def get_network():
    return get_all_network_packets()

@app.get("/api/simulate/{pid}")
async def simulate_pid(pid: int):
    return get_process_simulation_data(pid)

@app.post("/api/action/{action}/{pid}")
async def process_action(action: str, pid: int):
    import psutil
    try:
        proc = psutil.Process(pid)
        if action == "kill":
            proc.kill()
        elif action == "suspend":
            proc.suspend()
        elif action == "resume":
            proc.resume()
        else:
            return {"success": False, "error": "Unknown action"}
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/strings/{pid}")
async def get_process_strings(pid: int):
    return extract_strings(pid)

@app.get("/api/dump/{pid}")
async def dump_process_memory(pid: int):
    from fastapi.responses import JSONResponse
    dmp_path = generate_minidump(pid)
    if not dmp_path:
        return JSONResponse({"error": "Failed to generate minidump or access denied."}, status_code=500)
    return FileResponse(dmp_path, media_type='application/octet-stream', filename=f'process_{pid}.dmp')

# In-memory track of logged threat PIDs to avoid spamming the DB
logged_threats = set()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Analyze current processes
            sys_metrics, processes, threats, escalations, active_connections = analyze_processes()
            
            # Log new threats to DB
            for t in threats:
                if t['pid'] not in logged_threats:
                    log_threat(t)
                    logged_threats.add(t['pid'])
            
            payload = {
                "system": sys_metrics,
                "processes": processes,
                "threats": threats,
                "escalations": escalations,
                "active_connections": active_connections
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(2) # Send updates every 2 seconds
            
    except WebSocketDisconnect:
        print("Client disconnected")
    except Exception as e:
        print(f"WebSocket error: {e}")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
