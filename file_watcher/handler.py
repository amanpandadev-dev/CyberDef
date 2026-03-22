"""Auto-analysis callback for FileWatcher."""
from __future__ import annotations

from pathlib import Path
from core.logging import get_logger
logger = get_logger(__name__)

async def handle_new_csv(csv_path: Path) -> None:
    import httpx
    filename = csv_path.name
    logger.info(f"Auto-processing detected CSV | file={filename}")
    try: content = csv_path.read_bytes()
    except Exception as e:
        logger.error(f"Failed to read file | file={filename}, error={e}")
        return
    api_base = "http://127.0.0.1:8000/api/v1"
    async with httpx.AsyncClient(timeout=600.0) as client:
        logger.info(f"Auto-upload starting | file={filename}")
        try:
            resp = await client.post(f"{api_base}/files/upload", files={"file": (filename, content, "text/csv")})
            if resp.status_code != 201:
                logger.error(f"Auto-upload failed | status={resp.status_code}")
                return
            file_id = resp.json()["file_id"]
            logger.info(f"Auto-upload complete | file={filename}, file_id={file_id}")
        except Exception as e:
            logger.error(f"Auto-upload error | error={e}")
            return
        logger.info(f"Auto-analysis starting | file={filename}, file_id={file_id}")
        try:
            resp = await client.post(f"{api_base}/analyze", params={"file_id": file_id})
            if resp.status_code == 200:
                result = resp.json()
                logger.info(f"Auto-analysis complete | file={filename}, incidents={result.get('total_incidents', 0)}, report={result.get('report_path', '')}")
            else:
                logger.error(f"Auto-analysis failed | status={resp.status_code}")
        except Exception as e:
            logger.error(f"Auto-analysis error | error={e}")
