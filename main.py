import requests
import dns.resolver
import argparse
import sys
import time
import random
import re
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from Utils.Finder import SubdomainFinder

def main():
    parser = argparse.ArgumentParser(description='서브도메인 파인더')
    parser.add_argument('-d', '--domain', required=True, help='대상 도메인 (예: example.com)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='활성화 확인에 사용할 스레드 수 (기본값: 20)')
    parser.add_argument('-o', '--output', help='결과를 저장할 파일 경로')
    parser.add_argument('-v', '--verbose', action='store_true', help='모든 디버깅 메시지 표시')
    parser.add_argument('--timeout', type=int, default=10, help='요청 타임아웃 (초, 기본값: 10)')

    args = parser.parse_args()

    print("=" * 70)
    print(f"도메인 {args.domain} 서브도메인 찾기 시작")
    print("=" * 70)

    finder = SubdomainFinder(
        domain=args.domain,
        threads=args.threads,
        timeout=args.timeout,
        verbose=args.verbose
    )

    subdomains = finder.run()

    if args.output and subdomains:
        with open(args.output, 'w') as file:
            for subdomain in subdomains:
                file.write(f"{subdomain}\n")
        print(f"[+] 결과 파일 저장됨 :{args.output}")
    print(f"검색 완료: {len(subdomains)}개의 활성 서브도메인 발견")


if __name__ == "__main__":
    main()