import requests
import dns.resolver
import time
import random
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse


class SubdomainFinder:
    def __init__(self, domain, threads=20, timeout=10, verbose=False):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.subdomains = set()
        self.active_subdomains = set()
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"
        ]

    def get_random_user_agent(self):
        return random.choice(self.user_agents)

    def log(self, message):
        if self.verbose:
            print(message)
        elif message.startswith("[+]") or message.startswith("[!]"):
            print(message)

    def extract_subdomains_from_text(self, text):
        pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' + re.escape(self.domain)
        found = re.findall(pattern, text)

        result = []
        for subdomain in found:
            if subdomain.endswith(f".{self.domain}"):
                prefix = subdomain[:-(len(self.domain) + 1)]
                if prefix:
                    result.append(prefix)

        return result

    def find_from_crt_sh(self):
        self.log("[*] crt.sh에서 서브도메인 수집 중...")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            headers = {'User-Agent': self.get_random_user_agent()}
            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                try:
                    data = response.json()
                    if data:
                        for entry in data:
                            domain_names = entry.get('name_value', '').split('\n')
                            for domain_name in domain_names:
                                if '*.' in domain_name:
                                    domain_name = domain_name.replace('*.', '')
                                if domain_name.endswith(f".{self.domain}"):
                                    subdomain = domain_name[:-(len(self.domain) + 1)]
                                    if subdomain:
                                        self.subdomains.add(subdomain)
                except:
                    pass

                self.log(f"[+] crt.sh에서 {len(self.subdomains)}개의 서브도메인 찾음")
        except Exception as e:
            self.log(f"[!] crt.sh 조회 중 오류: {str(e)}")

    def find_from_securitytrails(self):
        self.log("[*] SecurityTrails에서 서브도메인 수집 중...")
        try:
            url = f"https://securitytrails.com/list/apex_domain/{self.domain}"
            headers = {'User-Agent': self.get_random_user_agent()}
            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                found = self.extract_subdomains_from_text(response.text)
                for subdomain in found:
                    self.subdomains.add(subdomain)

                self.log(f"[+] SecurityTrails에서 {len(found)}개의 서브도메인 찾음")
        except Exception as e:
            self.log(f"[!] SecurityTrails 조회 중 오류: {str(e)}")

    def find_from_virustotal(self):
        self.log("[*] VirusTotal에서 서브도메인 수집 중...")
        try:
            url = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40"
            headers = {'User-Agent': self.get_random_user_agent()}
            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                items = data.get('data', [])

                for item in items:
                    subdomain_id = item.get('id', '')
                    if subdomain_id.endswith(f".{self.domain}"):
                        subdomain = subdomain_id[:-(len(self.domain) + 1)]
                        if subdomain:
                            self.subdomains.add(subdomain)

                self.log(f"[+] VirusTotal에서 {len(items)}개의 서브도메인 찾음")
        except Exception as e:
            self.log(f"[!] VirusTotal 조회 중 오류: {str(e)}")

    def find_from_rapiddns(self):
        self.log("[*] RapidDNS에서 서브도메인 수집 중...")
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}"
            headers = {'User-Agent': self.get_random_user_agent()}
            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                found = self.extract_subdomains_from_text(response.text)
                for subdomain in found:
                    self.subdomains.add(subdomain)

                self.log(f"[+] RapidDNS에서 {len(found)}개의 서브도메인 찾음")
        except Exception as e:
            self.log(f"[!] RapidDNS 조회 중 오류: {str(e)}")

    def find_from_dnsdumpster(self):
        self.log("[*] DNSDumpster에서 서브도메인 수집 중...")
        try:
            session = requests.Session()
            headers = {'User-Agent': self.get_random_user_agent()}

            r = session.get("https://dnsdumpster.com/", headers=headers, timeout=self.timeout)
            csrf_token = re.search(r'name="csrfmiddlewaretoken" value="(.*?)"', r.text).group(1)

            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': self.domain,
                'user': 'free'
            }

            headers['Referer'] = 'https://dnsdumpster.com/'
            r = session.post("https://dnsdumpster.com/", headers=headers, data=data, timeout=self.timeout)

            found = self.extract_subdomains_from_text(r.text)
            for subdomain in found:
                self.subdomains.add(subdomain)

            self.log(f"[+] DNSDumpster에서 {len(found)}개의 서브도메인 찾음")
        except Exception as e:
            self.log(f"[!] DNSDumpster 조회 중 오류: {str(e)}")

    def find_from_alienvault(self):
        self.log("[*] AlienVault OTX에서 서브도메인 수집 중...")
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            headers = {'User-Agent': self.get_random_user_agent()}
            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                passive_dns = data.get('passive_dns', [])

                for entry in passive_dns:
                    hostname = entry.get('hostname', '')
                    if hostname.endswith(f".{self.domain}"):
                        subdomain = hostname[:-(len(self.domain) + 1)]
                        if subdomain:
                            self.subdomains.add(subdomain)

                self.log(f"[+] AlienVault OTX에서 {len(passive_dns)}개의 서브도메인 찾음")
        except Exception as e:
            self.log(f"[!] AlienVault OTX 조회 중 오류: {str(e)}")

    def find_from_hackertarget(self):
        self.log("[*] HackerTarget에서 서브도메인 수집 중...")
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            headers = {'User-Agent': self.get_random_user_agent()}
            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200 and not response.text.startswith('error') and len(response.text) > 0:
                results = response.text.split('\n')

                for result in results:
                    if result:
                        parts = result.split(',')
                        if len(parts) >= 1:
                            hostname = parts[0]
                            if hostname.endswith(f".{self.domain}"):
                                subdomain = hostname[:-(len(self.domain) + 1)]
                                if subdomain:
                                    self.subdomains.add(subdomain)

                self.log(f"[+] HackerTarget에서 {len(results)}개의 서브도메인 찾음")
        except Exception as e:
            self.log(f"[!] HackerTarget 조회 중 오류: {str(e)}")

    def find_from_waybackmachine(self):
        self.log("[*] Wayback Machine에서 서브도메인 수집 중...")
        try:
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
            headers = {'User-Agent': self.get_random_user_agent()}
            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                try:
                    data = response.json()
                    if data and len(data) > 0:
                        for line in data[1:]:
                            if line and len(line) > 0:
                                url_str = line[0]
                                try:
                                    parsed_url = urlparse(url_str)
                                    netloc = parsed_url.netloc

                                    if netloc.endswith(f".{self.domain}"):
                                        subdomain = netloc[:-(len(self.domain) + 1)]
                                        if subdomain:
                                            self.subdomains.add(subdomain)
                                except:
                                    pass
                except:
                    self.log("[!] Wayback Machine 응답 처리 중 오류 발생")

                self.log(f"[+] Wayback Machine에서 서브도메인 찾음")
        except Exception as e:
            self.log(f"[!] Wayback Machine 조회 중 오류: {str(e)}")

    def check_subdomain_active(self, subdomain):
        full_domain = f"{subdomain}.{self.domain}"
        try:
            dns.resolver.resolve(full_domain, 'A')
            return True
        except:
            try:
                dns.resolver.resolve(full_domain, 'AAAA')
                return True
            except:
                try:
                    dns.resolver.resolve(full_domain, 'CNAME')
                    return True
                except:
                    try:
                        requests.get(f"http://{full_domain}", timeout=self.timeout / 2)
                        return True
                    except:
                        try:
                            requests.get(f"https://{full_domain}", timeout=self.timeout / 2)
                            return True
                        except:
                            return False

    def verify_subdomains(self):
        self.log(f"[*] {len(self.subdomains)}개의 서브도메인 활성화 여부 확인 중...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_subdomain_active, subdomain): subdomain for subdomain in
                       self.subdomains}
            total = len(futures)
            completed = 0

            for future in futures:
                subdomain = futures[future]
                try:
                    is_active = future.result()
                    if is_active:
                        full_domain = f"{subdomain}.{self.domain}"
                        self.active_subdomains.add(full_domain)
                        print(f"[+] 활성 서브도메인 발견: {full_domain}")
                except Exception as e:
                    self.log(f"[!] 서브도메인 {subdomain} 확인 중 오류 발생: {str(e)}")

                completed += 1
                if completed % 10 == 0 or completed == total:
                    print(f"[*] 진행 상황: {completed}/{total} ({completed / total * 100:.1f}%)")

    def run(self):
        start_time = time.time()
        print(f"[*] 도메인 {self.domain}에 대한 서브도메인 수집 시작")

        with ThreadPoolExecutor(max_workers=8) as executor:
            sources = [
                self.find_from_crt_sh,
                self.find_from_securitytrails,
                self.find_from_virustotal,
                self.find_from_rapiddns,
                self.find_from_dnsdumpster,
                self.find_from_alienvault,
                self.find_from_hackertarget,
                self.find_from_waybackmachine
            ]

            for _ in executor.map(lambda x: x(), sources):
                pass

        print(f"[*] 총 {len(self.subdomains)}개의 고유한 서브도메인 발견")

        if self.subdomains:
            self.verify_subdomains()

            elapsed_time = time.time() - start_time
            print(
                f"\n[*] 검색 완료: {len(self.subdomains)}개 발견, {len(self.active_subdomains)}개 활성화 ({elapsed_time:.2f}초 소요)")

            return sorted(list(self.active_subdomains))
        else:
            print("[!] 서브도메인을 찾지 못했습니다.")
            return []