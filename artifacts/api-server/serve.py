"""Run the original FastAPI backend using the artifact-assigned port."""
import os
import uvicorn

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="0.0.0.0", port=int(os.environ["PORT"]))