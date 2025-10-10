# optimization.py - Performance optimizations
import asyncio
import aiohttp
import time
import security_hardening

class OptimizedScanner:
    """Optimized version of vulnerability scanner using async/await"""

    def __init__(self, max_concurrent=10):
        self.max_concurrent = max_concurrent
        self.session = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        self.session = aiohttp.ClientSession(connector=connector)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    async def fetch_url(self, url, method='GET', data=None):
        """Async URL fetching"""
        try:
            async with self.session.request(method, url, data=data, timeout=10) as response:
                content = await response.text()
                return {
                    'url': url,
                    'status': response.status,
                    'content': content,
                    'headers': dict(response.headers)
                }
        except Exception as e:
            return {'url': url, 'error': str(e)}

    async def crawl_async(self, target_url, max_pages=50):
        """Async web crawling"""
        visited = set()
        to_visit = [target_url]
        forms = []

        while to_visit and len(visited) < max_pages:
            # Process URLs in batches
            batch_size = min(self.max_concurrent, len(to_visit))
            batch = to_visit[:batch_size]
            to_visit = to_visit[batch_size:]

            # Fetch URLs concurrently
            tasks = [self.fetch_url(url) for url in batch]
            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for response in responses:
                if isinstance(response, dict) and 'content' in response:
                    url = response['url']
                    if url not in visited:
                        visited.add(url)

                        # Parse response and extract forms/links
                        # (Simplified - would use BeautifulSoup in real implementation)
                        if '<form' in response['content']:
                            forms.append({
                                'url': url,
                                'content': response['content'][:500]  # Truncated for demo
                            })

        return {
            'visited_urls': list(visited),
            'forms': forms,
            'total_pages': len(visited)
        }

    async def test_xss_async(self, forms, payloads):
        """Async XSS testing"""
        vulnerabilities = []
        tasks = []

        for form in forms:
            for payload in payloads[:5]:  # Limit payloads for demo
                # Create test task
                task = self.test_single_xss(form['url'], payload)
                tasks.append(task)

        # Execute tests concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict) and result.get('vulnerable'):
                vulnerabilities.append(result)

        return vulnerabilities

    async def test_single_xss(self, url, payload):
        """Test single XSS payload"""
        try:
            test_url = f"{url}?test={payload}"
            response = await self.fetch_url(test_url)

            if payload in response.get('content', ''):
                return {
                    'vulnerable': True,
                    'url': url,
                    'payload': payload,
                    'type': 'XSS'
                }
        except:
            pass

        return {'vulnerable': False}


# Example comprehensive test runner
def run_comprehensive_tests():
    """Run all test suites"""
    print("=" * 60)
    print("COMPREHENSIVE VULNERABILITY SCANNER TEST SUITE")
    print("=" * 60)

    # Unit tests
    print("\n1. Running Unit Tests...")
    unittest.main(argv=[''], verbosity=2, exit=False)

    # Performance tests
    print("\n2. Running Performance Tests...")
    perf_suite = PerformanceTestSuite()

    # Test with a safe target
    test_url = "http://testphp.vulnweb.com"

    try:
        # Crawler performance
        crawler_perf = perf_suite.test_crawler_performance(test_url, max_pages=20)

        # Concurrent scan performance
        concurrent_perf = perf_suite.test_concurrent_scans(test_url, num_threads=3)

        # Memory usage test
        memory_usage = perf_suite.test_memory_usage(test_url)

        print("\nPerformance Test Results:")
        print(f"- Crawler: {crawler_perf['pages_per_second']:.2f} pages/sec")
        print(f"- Concurrent: {concurrent_perf['scans_per_second']:.2f} scans/sec")
        print(f"- Memory usage: {memory_usage['memory_increase_mb']:.1f} MB increase")

    except Exception as e:
        print(f"Performance tests failed: {e}")

    # Security validation
    print("\n3. Running Security Validation...")
    security = security_hardening()

    try:
        # Test URL validation
        security.validate_target_url("https://example.com")
        print("✓ URL validation working")

        try:
            security.validate_target_url("http://localhost")
            print("✗ URL validation failed - localhost should be blocked")
        except ValueError:
            print("✓ Localhost blocking working")

        # Test token generation
        token = security.generate_scan_token()
        print(f"✓ Scan token generated: {token[:16]}...")

    except Exception as e:
        print(f"Security validation failed: {e}")

    print("\n" + "=" * 60)
    print("TEST SUITE COMPLETED")
    print("=" * 60)


# Example async usage
async def demo_async_scanning():
    """Demonstrate async scanning capabilities"""
    print("Demonstrating Async Scanning...")

    async with OptimizedScanner(max_concurrent=5) as scanner:
        # Async crawling
        start_time = time.time()
        results = await scanner.crawl_async("http://testphp.vulnweb.com", max_pages=10)
        crawl_time = time.time() - start_time

        print(f"Async crawl completed in {crawl_time:.2f}s")
        print(f"Found {len(results['visited_urls'])} pages and {len(results['forms'])} forms")

        # Async vulnerability testing
        if results['forms']:
            xss_payloads = ['<script>alert("test")</script>', '<img src=x onerror=alert(1)>']
            start_time = time.time()
            vulns = await scanner.test_xss_async(results['forms'], xss_payloads)
            test_time = time.time() - start_time

            print(f"Async vulnerability testing completed in {test_time:.2f}s")
            print(f"Found {len(vulns)} potential vulnerabilities")


if __name__ == "__main__":
    print("Web Application Vulnerability Scanner - Testing & Optimization Suite")
    print("\nAvailable test modes:")
    print("1. Unit Tests - python -m unittest tests.test_scanner")
    print("2. Performance Tests - python performance_tests.py")
    print(
        "3. Async Demo - python -c 'import asyncio; from phase6 import demo_async_scanning; asyncio.run(demo_async_scanning())'")
    print("4. Full Test Suite - python phase6.py")

    # Run comprehensive tests
    run_comprehensive_tests()

    # Demo async scanning
    print("\n" + "=" * 60)
    print("ASYNC SCANNING DEMONSTRATION")
    print("=" * 60)
    asyncio.run(demo_async_scanning())