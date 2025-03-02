import time
import os
from typing import List, Optional
from fastapi import FastAPI, BackgroundTasks, Query, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, constr, validator
import uuid

from Utils.Finder import SubdomainFinder

app = FastAPI(
    title="서브도메인 파인더 API",
    description="서브도메인 파인더",
    version="1.0.0"
)

RESULTS_CACHE = {}
TEMP_DIR = "temp_results"

os.makedirs(TEMP_DIR, exist_ok=True)


class ScanRequest(BaseModel):
    domain: constr(min_length=4)
    threads: int = 20
    timeout: int = 10
    verbose: bool = False

    @validator('domain')
    def validate_domain(cls, v):
        if not '.' in v:
            raise ValueError('도메인에는 최소한 하나의 점이 포함되어야 합니다')
        return v


class ScanResponse(BaseModel):
    scan_id: str
    domain: str
    status: str = "pending"
    message: str = "스캔이 대기열에 추가되었습니다"


class ScanResult(BaseModel):
    scan_id: str
    domain: str
    status: str
    total_found: int = 0
    active_subdomains: List[str] = []
    elapsed_time: float = 0.0
    message: Optional[str] = None


def run_subdomain_scan(scan_id: str, domain: str, threads: int, timeout: int, verbose: bool):
    start_time = time.time()

    try:
        RESULTS_CACHE[scan_id]["status"] = "running"

        finder = SubdomainFinder(
            domain=domain,
            threads=threads,
            timeout=timeout,
            verbose=verbose
        )

        subdomains = finder.run()

        result_file = os.path.join(TEMP_DIR, f"{scan_id}.txt")
        with open(result_file, 'w') as file:
            for subdomain in subdomains:
                file.write(f"{subdomain}\n")

        RESULTS_CACHE[scan_id].update({
            "status": "completed",
            "total_found": len(subdomains),
            "active_subdomains": subdomains,
            "elapsed_time": time.time() - start_time,
            "result_file": result_file
        })
    except Exception as e:
        RESULTS_CACHE[scan_id].update({
            "status": "failed",
            "message": str(e),
            "elapsed_time": time.time() - start_time
        })


@app.post("/scan", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())

    RESULTS_CACHE[scan_id] = {
        "scan_id": scan_id,
        "domain": scan_request.domain,
        "status": "pending",
        "total_found": 0,
        "active_subdomains": []
    }

    background_tasks.add_task(
        run_subdomain_scan,
        scan_id,
        scan_request.domain,
        scan_request.threads,
        scan_request.timeout,
        scan_request.verbose
    )

    return ScanResponse(
        scan_id=scan_id,
        domain=scan_request.domain
    )


@app.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan_result(scan_id: str):
    if scan_id not in RESULTS_CACHE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="스캔 ID를 찾을 수 없습니다"
        )

    result = RESULTS_CACHE[scan_id]
    return ScanResult(**result)


@app.get("/scan/{scan_id}/download")
async def download_results(scan_id: str):
    if scan_id not in RESULTS_CACHE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="스캔 ID를 찾을 수 없습니다"
        )

    result = RESULTS_CACHE[scan_id]

    if result["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"스캔이 완료되지 않았습니다. 현재 상태: {result['status']}"
        )

    if "result_file" not in result:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="결과 파일을 찾을 수 없습니다"
        )

    return FileResponse(
        path=result["result_file"],
        filename=f"{result['domain']}_subdomains.txt",
        media_type="text/plain"
    )


@app.get("/", status_code=status.HTTP_200_OK)
async def root():
    return {
        "message": "서브도메인 검색기 API가 실행 중입니다"
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)