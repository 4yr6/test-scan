#!/usr/bin/env python3
"""
AI API Key Leak Monitor & Validator
24/7 监控泄漏的AI API key，并用智力测试验证有效性
扫描源：GitHub + Pastebin + GrepRepo + 公开泄露数据库
"""

import os
import sys
import time
import re
import json
import requests
import asyncio
import aiohttp
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import logging
from urllib.parse import quote
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api_key_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# API Key 模式匹配（扩展版）
KEY_PATTERNS = {
    'openai': r'(sk-[a-zA-Z0-9]{20,})',
    'anthropic': r'(sk-ant-[a-zA-Z0-9_-]{20,})',
    'cohere': r'(sk-[a-zA-Z0-9]{20,})',
    'google': r'(AIza[a-zA-Z0-9_-]{30,})',
    'azure_openai': r'(https://[a-zA-Z0-9.-]+\.openai\.azure\.com.*?api-key=[a-zA-Z0-9]{32,})',
    'huggingface': r'(hf_[a-zA-Z0-9_-]{20,}|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})',
    'aws': r'(AKIA[0-9A-Z]{16})',
    'stripe': r'(sk_live_[a-zA-Z0-9]{24,}|sk_test_[a-zA-Z0-9]{24,})',
}

# 智力测试问题库
QUIZ_QUESTIONS = [
    {"question": "什么是量子纠缠？", "category": "physics"},
    {"question": "解释一下递归函数的工作原理", "category": "programming"},
    {"question": "如何训练一个Transformer模型？", "category": "ml"},
    {"question": "Python中装饰器的作用是什么？", "category": "programming"},
    {"question": "什么是区块链的共识机制？", "category": "crypto"},
]


class KeyScanner:
    """扫描公开的API key泄露"""

    def __init__(self):
        self.seen_keys = set()
        self.found_keys = []
        self.github_token = os.getenv('GITHUB_TOKEN', '')

    def scan_github(self, queries: List[str] = None) -> List[str]:
        """扫描GitHub公开仓库中的API key"""
        keys = []
        if queries is None:
            queries = ['api_key', 'sk-', 'secret', 'token', 'password', 'credential']

        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'AI-Key-Monitor/1.0'
        }
        if self.github_token:
            headers['Authorization'] = f'token {self.github_token}'

        for query in queries:
            try:
                # GitHub Search API - 搜索代码中的敏感信息
                search_query = f"{query} in:file"
                url = f"https://api.github.com/search/code?q={search_query}&per_page=100&sort=created&order=desc"

                response = requests.get(url, headers=headers, timeout=15)

                if response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    logger.info(f"GitHub搜索 '{query}' 返回 {len(items)} 个结果")

                    # 获取每个文件的实际内容来提取key
                    for item in items[:20]:  # 限制处理数量避免超时
                        try:
                            html_url = item.get('html_url', '')
                            # 从URL中提取repo信息: github.com/owner/repo/blob/branch/path/filename
                            match = re.search(r'github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)', html_url)
                            if match:
                                owner, repo, branch, filepath = match.groups()
                                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{filepath}"
                                content_resp = requests.get(raw_url, timeout=10)
                                if content_resp.status_code == 200:
                                    for pattern in KEY_PATTERNS.values():
                                        matches = re.findall(pattern, content_resp.text)
                                        if matches:
                                            logger.debug(f"在 {html_url} 发现 {len(matches)} 个匹配")
                                            keys.extend(matches)
                        except Exception as e:
                            logger.debug(f"获取文件内容失败: {e}")
                            continue

                elif response.status_code == 403:
                    logger.warning("GitHub API限流，尝试使用备用扫描方式")
                    self._scan_known_dumps(keys)
                elif response.status_code == 401:
                    logger.warning("GitHub未认证，使用备用扫描源")
                    self._scan_known_dumps(keys)
                else:
                    logger.debug(f"GitHub搜索 '{query}' 返回状态码: {response.status_code}")

            except Exception as e:
                logger.error(f"GitHub搜索 '{query}' 出错: {e}")

        return list(set(keys))

    def _scan_known_dumps(self, keys: List[str]) -> List[str]:
        """扫描已知的公开泄露dump文件"""
        found_keys = list(keys) if keys else []
        dump_sources = [
            # GrepRepo - 公开的敏感信息泄露搜索
            ("https://greprepo.com/api/search?q=api_key&limit=50", "json"),
            ("https://greprepo.com/api/search?q=sk-&limit=50", "json"),
            # Public leak databases
            ("https://raw.githubusercontent.com/soxoj/compromised-secrets/main/data/dumps.json", "json"),
            # Pastebin 搜索
            ("https://pastebin.com/search/all/api_key", "html"),
            ("https://pastebin.com/search/all/sk-", "html"),
            ("https://pastebin.com/search/all/secret", "html"),
        ]

        for url, source_type in dump_sources:
            try:
                resp = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
                if resp.status_code == 200:
                    if source_type == "json":
                        try:
                            data = resp.json()
                            # 尝试不同格式
                            if isinstance(data, dict):
                                items = data.get('data', data.get('results', [data]))
                            else:
                                items = data if isinstance(data, list) else []

                            for item in items:
                                content = item.get('content', item.get('text', str(item)))
                                for pattern in KEY_PATTERNS.values():
                                    matches = re.findall(pattern, content)
                                    found_keys.extend(matches)
                        except json.JSONDecodeError:
                            # 不是JSON，当文本处理
                            for pattern in KEY_PATTERNS.values():
                                matches = re.findall(pattern, resp.text)
                                found_keys.extend(matches)
                    else:
                        # HTML格式，提取链接和文本
                        links = re.findall(r'href="([^"]+)"', resp.text)
                        for link in links:
                            if '/raw/' in link or 'pastebin.com/raw' in link:
                                try:
                                    raw_resp = requests.get(link, timeout=5)
                                    if raw_resp.status_code == 200:
                                        for pattern in KEY_PATTERNS.values():
                                            matches = re.findall(pattern, raw_resp.text)
                                            found_keys.extend(matches)
                                except:
                                    pass
            except Exception as e:
                logger.debug(f"扫描源 {url} 出错: {e}")

        return list(set(found_keys))

    def scan_pastebin(self, query: str = "api_key") -> List[str]:
        """扫描Pastebin泄露"""
        keys = []
        keywords = ['api_key', 'sk-', 'secret', 'token', 'password', 'credential']

        for keyword in keywords:
            try:
                # Pastebin搜索（公开端点）
                url = f"https://pastebin.com/search/all/{keyword}"
                response = requests.get(url, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }, timeout=10)

                if response.status_code == 200:
                    # 提取pastebin raw链接
                    raw_links = re.findall(r'https://pastebin\.com/raw/[a-zA-Z0-9]+', response.text)
                    for link in raw_links[:5]:  # 限制数量
                        try:
                            raw_resp = requests.get(link, timeout=5)
                            if raw_resp.status_code == 200:
                                for pattern in KEY_PATTERNS.values():
                                    matches = re.findall(pattern, raw_resp.text)
                                    keys.extend(matches)
                        except:
                            pass
            except Exception as e:
                logger.debug(f"Pastebin搜索 '{keyword}' 出错: {e}")

        return list(set(keys))

    def scan_github_repos(self) -> List[str]:
        """扫描已知的敏感信息泄露仓库"""
        keys = []
        # 公开的安全研究仓库，包含各种API key样本
        repo_list = [
            "trufflesecurity/trufflehog",  # 开源的密钥扫描工具
            "GitGuardian/apidojo",  # API安全相关
        ]

        for repo in repo_list:
            try:
                # 获取仓库文件列表
                url = f"https://api.github.com/repos/{repo}/git/trees/main?recursive=1"
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    tree = resp.json().get('tree', [])
                    for item in tree[:50]:  # 限制数量
                        path = item.get('path', '')
                        if any(k in path.lower() for k in ['key', 'secret', 'token', 'credential']):
                            blob_url = f"https://raw.githubusercontent.com/{repo}/main/{path}"
                            content_resp = requests.get(blob_url, timeout=5)
                            if content_resp.status_code == 200:
                                for pattern in KEY_PATTERNS.values():
                                    matches = re.findall(pattern, content_resp.text)
                                    keys.extend(matches)
            except Exception as e:
                logger.debug(f"扫描仓库 {repo} 出错: {e}")

        return list(set(keys))

    def scan_curl_secrets(self) -> List[str]:
        """扫描公开的curl secrets数据库"""
        keys = []
        try:
            # 使用公共的secret scanning API
            endpoints = [
                "https://raw.githubusercontent.com/dxa4481/truffleHogRegexes/master/regexes.json",
            ]
            for url in endpoints:
                resp = requests.get(url, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    # 提取可能的key模式
                    for item in data:
                        pattern = item.get('regex', '')
                        try:
                            compiled = re.compile(pattern)
                            # 用已知泄露的样本测试（这里只是演示）
                        except:
                            pass
        except Exception as e:
            logger.debug(f"扫描curl secrets出错: {e}")
        return keys

    def detect_key_type(self, key: str) -> str:
        """检测key类型"""
        for name, pattern in KEY_PATTERNS.items():
            if re.match(pattern, key):
                return name
        return "unknown"


class KeyValidator:
    """验证API key有效性并进行智力测试"""

    def __init__(self):
        self.api_keys = {}

    async def test_openai(self, key: str) -> Dict:
        """测试OpenAI API key"""
        headers = {"Authorization": f"Bearer {key}"}
        try:
            async with aiohttp.ClientSession() as session:
                # 先用简单请求测试key有效性
                async with session.get(
                    "https://api.openai.com/v1/models",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        quiz_result = await self.run_intelligence_test(key)
                        return {
                            "status": "valid",
                            "key_preview": f"{key[:8]}...{key[-4:]}",
                            "quiz_passed": quiz_result.get("passed", False),
                            "quiz_score": quiz_result.get("score", 0)
                        }
                    else:
                        return {
                            "status": f"invalid ({resp.status})",
                            "key_preview": f"{key[:8]}...{key[-4:]}"
                        }
        except Exception as e:
            logger.error(f"OpenAI测试失败: {e}")
            return {"status": "error", "error": str(e)}

    async def test_anthropic(self, key: str) -> Dict:
        """测试Anthropic API key"""
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01"
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.anthropic.com/v1/messages",
                    json={
                        "model": "claude-3-haiku-20240307",
                        "max_tokens": 64,
                        "messages": [{"role": "user", "content": "Hi"}]
                    },
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        quiz_result = await self.run_intelligence_test(key)
                        return {
                            "status": "valid",
                            "key_preview": f"{key[:8]}...{key[-4:]}",
                            "quiz_passed": quiz_result.get("passed", False),
                            "quiz_score": quiz_result.get("score", 0)
                        }
                    else:
                        return {
                            "status": f"invalid ({resp.status})",
                            "key_preview": f"{key[:8]}...{key[-4:]}"
                        }
        except Exception as e:
            logger.error(f"Anthropic测试失败: {e}")
            return {"status": "error", "error": str(e)}

    async def run_intelligence_test(self, key: str, provider: str = "openai") -> Dict:
        """运行智力测试"""
        correct_answers = 0
        total_questions = len(QUIZ_QUESTIONS)

        test_content = []
        for q in QUIZ_QUESTIONS:
            prompt = f"请回答以下问题：{q['question']}"

            try:
                if provider == "openai":
                    response = await self._call_openai_api(key, prompt)
                else:
                    response = await self._call_anthropic_api(key, prompt)

                test_content.append({
                    "question": q["question"],
                    "answer": response.get("content", "")[:200],
                    "category": q["category"]
                })

                if len(response.get("content", "")) > 10:
                    correct_answers += 1

            except Exception as e:
                logger.error(f"智力测试失败: {e}")
                continue

        return {
            "passed": correct_answers >= total_questions * 0.5,
            "score": f"{correct_answers}/{total_questions}",
            "details": test_content
        }

    async def _call_openai_api(self, key: str, prompt: str) -> Dict:
        """调用OpenAI API"""
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.openai.com/v1/chat/completions",
                json={
                    "model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 200
                },
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                data = await resp.json()
                return {"content": data["choices"][0]["message"]["content"]}

    async def _call_anthropic_api(self, key: str, prompt: str) -> Dict:
        """调用Anthropic API"""
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://api.anthropic.com/v1/messages",
                json={
                    "model": "claude-3-haiku-20240307",
                    "max_tokens": 200,
                    "messages": [{"role": "user", "content": prompt}]
                },
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                data = await resp.json()
                return {"content": data["content"][0]["text"]}


class MonitorScheduler:
    """24/7 监控调度器"""

    def __init__(self):
        self.scanner = KeyScanner()
        self.validator = KeyValidator()
        self.running = False

    async def scan_cycle(self):
        """执行一次扫描周期 - 扫描所有可用源"""
        logger.info("=" * 60)
        logger.info(f"开始全量扫描周期: {datetime.now().isoformat()}")

        all_keys = []

        # 1. GitHub代码搜索（需要token）
        logger.info("正在扫描GitHub...")
        github_keys = self.scanner.scan_github()
        all_keys.extend(github_keys)
        logger.info(f"GitHub发现 {len(github_keys)} 个key")

        # 2. Pastebin搜索
        logger.info("正在扫描Pastebin...")
        pastebin_keys = self.scanner.scan_pastebin()
        all_keys.extend(pastebin_keys)
        logger.info(f"Pastebin发现 {len(pastebin_keys)} 个key")

        # 3. GitHub已知泄露仓库
        logger.info("正在扫描GitHub泄露仓库...")
        repo_keys = self.scanner.scan_github_repos()
        all_keys.extend(repo_keys)
        logger.info(f"泄露仓库发现 {len(repo_keys)} 个key")

        # 4. 公开dump数据库
        logger.info("正在扫描公开泄露数据库...")
        dump_keys = self.scanner._scan_known_dumps([])
        all_keys.extend(dump_keys)
        logger.info(f"泄露数据库发现 {len(dump_keys)} 个key")

        # 去重并过滤已见过的
        all_keys = list(set(all_keys))
        unique_new_keys = [k for k in all_keys if k not in self.scanner.seen_keys]
        self.scanner.seen_keys.update(unique_new_keys)

        logger.info(f"本轮共发现 {len(all_keys)} 个key，其中 {len(unique_new_keys)} 个新key")

        if not unique_new_keys:
            logger.info("未发现新的泄漏key")
            return

        logger.info(f"发现 {len(unique_new_keys)} 个新key，开始验证...")

        # 2. 验证并测试（最多测试5个）
        results = []
        for key in unique_new_keys[:5]:
            key_type = self.scanner.detect_key_type(key)
            logger.info(f"测试 {key_type} key: {key[:8]}...{key[-4:]}")

            if key_type == "openai":
                result = await self.validator.test_openai(key)
            elif key_type == "anthropic":
                result = await self.validator.test_anthropic(key)
            else:
                result = {"status": "unknown type", "key_preview": f"{key[:8]}...{key[-4:]}"}

            results.append({"key": key, "type": key_type, "result": result})

            await asyncio.sleep(2)  # 避免请求过快

        # 3. 保存结果
        self._save_results(results)

    def _save_results(self, results: List[Dict]):
        """保存扫描结果"""
        output_file = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "total_scanned": len(results),
                "valid_keys": [r for r in results if r["result"].get("status") == "valid"],
                "invalid_keys": [r for r in results if r["result"].get("status", "").startswith("invalid")],
                "details": results
            }, f, indent=2, ensure_ascii=False)
        logger.info(f"结果已保存到: {output_file}")

    async def run_24_7(self, interval_hours: int = 6):
        """24/7 持续运行"""
        self.running = True
        logger.info(f"启动24/7全量监控，每{interval_hours}小时扫描一次")

        while self.running:
            try:
                await self.scan_cycle()
                wait_seconds = interval_hours * 3600
                logger.info(f"等待 {wait_seconds//3600} 小时后进行下一轮扫描...")
                await asyncio.sleep(wait_seconds)
            except KeyboardInterrupt:
                logger.info("收到中断信号，停止监控")
                self.running = False
            except Exception as e:
                logger.error(f"扫描周期出错: {e}")
                await asyncio.sleep(60)


async def main():
    """主函数"""
    import argparse
    parser = argparse.ArgumentParser(description="AI API Key Leak Monitor & Validator")
    parser.add_argument("--once", action="store_true", help="只执行一次全量扫描")
    parser.add_argument("--interval", type=int, default=6, help="24/7模式下的扫描间隔(小时)")
    args = parser.parse_args()

    monitor = MonitorScheduler()

    if args.once:
        await monitor.scan_cycle()
    else:
        await monitor.run_24_7(interval_hours=args.interval)


if __name__ == "__main__":
    asyncio.run(main())
