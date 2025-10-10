# performance_tests.py - Performance and load testing
import time
import requests
import statistics
from concurrent.futures import ThreadPoolExecutor
from scanner.crawler import WebCrawler
from scanner.vulnerabilities.xss import XSSScanner
from scanner.vulnerability_manager import VulnerabilityManager

class PerformanceTestSuite:
    """Performance testing for vulnerability scanner"""

    def __init__(self):
        self.results = []

    def test_crawler_performance(self, target_url, max_pages=100):
        """Test crawler performance with various page counts"""
        print(f"Testing crawler performance with {max_pages} pages...")

        start_time = time.time()
        crawler = WebCrawler(target_url, max_pages=max_pages)

        try:
            results = crawler.crawl()
            end_time = time.time()

            elapsed_time = end_time - start_time
            pages_per_second = len(results['visited_urls']) / elapsed_time

            print(f"Crawled {len(results['visited_urls'])} pages in {elapsed_time:.2f}s")
            print(f"Rate: {pages_per_second:.2f} pages/second")

            return {
                'pages_crawled': len(results['visited_urls']),
                'time_taken': elapsed_time,
                'pages_per_second': pages_per_second,
                'forms_found': len(results['forms'])
            }

        except Exception as e:
            print(f"Performance test failed: {e}")
            return None

    def test_concurrent_scans(self, target_url, num_threads=5):
        """Test concurrent scan performance"""
        print(f"Testing {num_threads} concurrent scans...")

        def run_single_scan():
            session = requests.Session()
            crawler = WebCrawler(target_url, max_pages=10)
            results = crawler.crawl()

            scanner = XSSScanner(session)
            vulnerabilities = scanner.scan(results)
            return len(vulnerabilities)

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(run_single_scan) for _ in range(num_threads)]
            results = [future.result() for future in futures]

        end_time = time.time()

        print(f"Completed {num_threads} scans in {end_time - start_time:.2f}s")
        print(f"Average vulnerabilities found: {statistics.mean(results):.1f}")

        return {
            'total_time': end_time - start_time,
            'scans_per_second': num_threads / (end_time - start_time),
            'vulnerability_results': results
        }

    def test_memory_usage(self, target_url):
        """Test memory usage during scanning"""
        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        print(f"Initial memory usage: {initial_memory:.1f} MB")

        # Run comprehensive scan
        session = requests.Session()
        crawler = WebCrawler(target_url, max_pages=50)
        results = crawler.crawl()

        manager = VulnerabilityManager(session)
        scan_results = manager.run_full_scan(results)

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory

        print(f"Final memory usage: {final_memory:.1f} MB")
        print(f"Memory increase: {memory_increase:.1f} MB")

        return {
            'initial_memory_mb': initial_memory,
            'final_memory_mb': final_memory,
            'memory_increase_mb': memory_increase
        }
