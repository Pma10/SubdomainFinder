import requests
import time

API_URL = "http://localhost:8000"

try:
    response = requests.get(API_URL)
    if response.status_code != 200:
        print(f"API 서버 연결 오류: 상태 코드 {response.status_code}")
        print(response.text)
        exit(1)
    else:
        print("API 서버 연결 성공!")

    domain = "example.com"
    scan_data = {
        "domain": domain,
        "threads": 20,
        "timeout": 10,
        "verbose": False
    }

    response = requests.post(f"{API_URL}/scan", json=scan_data)
    if response.status_code != 202:
        print(f"스캔 시작 오류: 상태 코드 {response.status_code}")
        print(response.text)
        exit(1)

    scan_result = response.json()
    scan_id = scan_result["scan_id"]
    print(f"스캔 시작됨: {scan_id}")

    max_retries = 60
    retries = 0

    while retries < max_retries:
        try:
            response = requests.get(f"{API_URL}/scan/{scan_id}")

            print(f"상태 코드: {response.status_code}")
            print(f"응답 내용: {response.text[:100]}...")

            if response.status_code != 200:
                print(f"결과 확인 오류: 상태 코드 {response.status_code}")
                time.sleep(5)
                retries += 1
                continue

            data = response.json()

            if data["status"] == "completed":
                print("스캔 완료!")
                print(f"발견된 서브도메인: {data['total_found']}개")
                if data['active_subdomains']:
                    print(f"활성 서브도메인 샘플: {', '.join(data['active_subdomains'][:5])}...")
                break
            elif data["status"] == "failed":
                print(f"스캔 실패: {data.get('message', '알 수 없는 오류')}")
                break
            else:
                print(f"스캔 진행 중... 상태: {data['status']}")
                time.sleep(5)
                retries += 1
        except requests.exceptions.JSONDecodeError as e:
            print(f"JSON 디코딩 오류: {e}")
            print(f"응답 내용: {response.text}")
            time.sleep(5)
            retries += 1
        except Exception as e:
            print(f"오류 발생: {e}")
            time.sleep(5)
            retries += 1

    if retries < max_retries and data["status"] == "completed":
        try:
            response = requests.get(f"{API_URL}/scan/{scan_id}/download")
            if response.status_code == 200:
                with open(f"{domain}_subdomains.txt", "wb") as f:
                    f.write(response.content)
                print(f"결과 파일 저장됨: {domain}_subdomains.txt")
            else:
                print(f"결과 다운로드 실패: 상태 코드 {response.status_code}")
        except Exception as e:
            print(f"결과 다운로드 중 오류 발생: {e}")

except requests.exceptions.ConnectionError:
    print("API 서버에 연결할 수 없습니다. 서버가 실행 중인지 확인하세요.")
except Exception as e:
    print(f"예상치 못한 오류 발생: {e}")