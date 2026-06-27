#!/usr/bin/env python3
"""
NetLogic Security Testing Script
Run security tests and validate security posture.
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import List, Dict, Any


class SecurityTestResult:
    """Result of a security test."""

    def __init__(self, name: str, passed: bool, message: str, severity: str = "high"):
        self.name = name
        self.passed = passed
        self.message = message
        self.severity = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "message": self.message,
            "severity": self.severity,
        }


class SecurityTester:
    """Security testing framework for NetLogic."""

    def __init__(self):
        self.results: List[SecurityTestResult] = []
        self.project_root = Path(__file__).parent.parent

    def test_environment_variables(self) -> SecurityTestResult:
        """Test that required security environment variables are set."""
        required_vars = {
            "NETLOGIC_JWT_SECRET": "JWT signing secret",
            "NETLOGIC_ADMIN_KEY": "Admin API key",
        }

        missing_vars = []
        weak_vars = []

        for var, description in required_vars.items():
            value = os.environ.get(var, "")

            if not value:
                missing_vars.append(var)
            elif len(value) < 32:
                weak_vars.append(var)
            elif value in ["changeme", "admin-changeme", "changeme-in-production"]:
                weak_vars.append(var)

        if missing_vars:
            return SecurityTestResult(
                "Environment Variables",
                False,
                f"Missing required variables: {', '.join(missing_vars)}",
                "critical"
            )

        if weak_vars:
            return SecurityTestResult(
                "Environment Variables",
                False,
                f"Weak values for: {', '.join(weak_vars)} (must be 32+ chars)",
                "critical"
            )

        return SecurityTestResult(
            "Environment Variables",
            True,
            "All required security environment variables are properly configured"
        )

    def test_cors_configuration(self) -> SecurityTestResult:
        """Test CORS configuration is not overly permissive."""
        cors_origins = os.environ.get("NETLOGIC_CORS_ORIGINS", "")

        if cors_origins.strip() == "*":
            return SecurityTestResult(
                "CORS Configuration",
                False,
                "CORS allows wildcard origins (*) - this enables CSRF attacks",
                "critical"
            )

        if not cors_origins.strip():
            return SecurityTestResult(
                "CORS Configuration",
                True,
                "CORS is disabled (secure default)"
            )

        return SecurityTestResult(
            "CORS Configuration",
            True,
            f"CORS restricted to specific origins: {cors_origins}"
        )

    def test_dependencies(self) -> SecurityTestResult:
        """Test for known vulnerable dependencies."""
        try:
            result = subprocess.run(
                ["safety", "check", "--json"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                return SecurityTestResult(
                    "Dependency Vulnerabilities",
                    True,
                    "No known vulnerabilities found in dependencies"
                )
            else:
                try:
                    vulns = json.loads(result.stdout)
                    return SecurityTestResult(
                        "Dependency Vulnerabilities",
                        False,
                        f"Found {len(vulns)} known vulnerabilities in dependencies",
                        "high"
                    )
                except json.JSONDecodeError:
                    return SecurityTestResult(
                        "Dependency Vulnerabilities",
                        False,
                        "Failed to check dependencies (safety not installed?)",
                        "medium"
                    )

        except FileNotFoundError:
            return SecurityTestResult(
                "Dependency Vulnerabilities",
                False,
                "Safety tool not installed - run: pip install safety",
                "medium"
            )
        except subprocess.TimeoutExpired:
            return SecurityTestResult(
                "Dependency Vulnerabilities",
                False,
                "Dependency check timed out",
                "low"
            )

    def test_code_security(self) -> SecurityTestResult:
        """Test code for security issues using bandit."""
        try:
            result = subprocess.run(
                ["bandit", "-r", "src/", "api/", "-f", "json"],
                capture_output=True,
                text=True,
                timeout=60
            )

            try:
                bandit_output = json.loads(result.stdout)
                issues = bandit_output.get("results", [])

                if not issues:
                    return SecurityTestResult(
                        "Code Security Analysis",
                        True,
                        "No security issues found in code"
                    )

                high_severity = [i for i in issues if i.get("issue_severity") == "HIGH"]
                medium_severity = [i for i in issues if i.get("issue_severity") == "MEDIUM"]

                if high_severity:
                    return SecurityTestResult(
                        "Code Security Analysis",
                        False,
                        f"Found {len(high_severity)} high-severity security issues",
                        "high"
                    )

                if medium_severity:
                    return SecurityTestResult(
                        "Code Security Analysis",
                        False,
                        f"Found {len(medium_severity)} medium-severity security issues",
                        "medium"
                    )

                return SecurityTestResult(
                    "Code Security Analysis",
                    True,
                    f"Found {len(issues)} low-severity issues"
                )

            except json.JSONDecodeError:
                return SecurityTestResult(
                    "Code Security Analysis",
                    False,
                    "Failed to analyze code (bandit not installed?)",
                    "medium"
                )

        except FileNotFoundError:
            return SecurityTestResult(
                "Code Security Analysis",
                False,
                "Bandit tool not installed - run: pip install bandit",
                "medium"
            )
        except subprocess.TimeoutExpired:
            return SecurityTestResult(
                "Code Security Analysis",
                False,
                "Code analysis timed out",
                "low"
            )

    def test_file_permissions(self) -> SecurityTestResult:
        """Test that sensitive files have restrictive permissions."""
        sensitive_files = [
            ".env",
            "api_keys.json",
            "netlogic_config.json",
        ]

        issues = []
        for file_path in sensitive_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                stat = full_path.stat()
                mode = stat.st_mode & 0o777

                # Check if file is readable by others
                if mode & 0o044:  # Readable by others
                    issues.append(f"{file_path} is readable by others (mode: {oct(mode)})")

        if issues:
            return SecurityTestResult(
                "File Permissions",
                False,
                f"Permission issues: {', '.join(issues)}",
                "high"
            )

        return SecurityTestResult(
            "File Permissions",
            True,
            "All sensitive files have appropriate permissions"
        )

    def test_rate_limiting(self) -> SecurityTestResult:
        """Test that rate limiting is configured."""
        rate_limit_file = self.project_root / "api" / "auth" / "rate_limit.py"

        if not rate_limit_file.exists():
            return SecurityTestResult(
                "Rate Limiting",
                False,
                "Rate limiting module not found",
                "critical"
            )

        content = rate_limit_file.read_text()

        # Check for essential rate limiters
        required_limiters = [
            "token_limiter",
            "jobs_limiter",
            "ban_list",
        ]

        missing_limiters = [
            limiter for limiter in required_limiters if limiter not in content
        ]

        if missing_limiters:
            return SecurityTestResult(
                "Rate Limiting",
                False,
                f"Missing rate limiters: {', '.join(missing_limiters)}",
                "high"
            )

        return SecurityTestResult(
            "Rate Limiting",
            True,
            "Comprehensive rate limiting configured"
        )

    def test_security_headers(self) -> SecurityTestResult:
        """Test that security headers middleware is configured."""
        main_file = self.project_root / "api" / "main.py"

        if not main_file.exists():
            return SecurityTestResult(
                "Security Headers",
                False,
                "API main file not found",
                "critical"
            )

        content = main_file.read_text()

        # Check for security headers
        required_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Content-Security-Policy",
        ]

        missing_headers = [
            header for header in required_headers if header not in content
        ]

        if missing_headers:
            return SecurityTestResult(
                "Security Headers",
                False,
                f"Missing security headers: {', '.join(missing_headers)}",
                "high"
            )

        return SecurityTestResult(
            "Security Headers",
            True,
            "All required security headers configured"
        )

    def run_all_tests(self) -> List[SecurityTestResult]:
        """Run all security tests."""
        print("🔒 Running NetLogic Security Tests...\n")

        tests = [
            self.test_environment_variables,
            self.test_cors_configuration,
            self.test_dependencies,
            self.test_code_security,
            self.test_file_permissions,
            self.test_rate_limiting,
            self.test_security_headers,
        ]

        for test in tests:
            try:
                result = test()
                self.results.append(result)

                status = "✅" if result.passed else "❌"
                severity = f"[{result.severity.upper()}]" if not result.passed else ""
                print(f"{status} {result.name} {severity}")
                if not result.passed:
                    print(f"   {result.message}\n")

            except Exception as e:
                error_result = SecurityTestResult(
                    test.__name__,
                    False,
                    f"Test failed with exception: {str(e)}",
                    "error"
                )
                self.results.append(error_result)
                print(f"❌ {test.__name__} [ERROR]")
                print(f"   Test failed with exception: {str(e)}\n")

        return self.results

    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive security report."""
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)

        critical_issues = [r for r in self.results if not r.passed and r.severity == "critical"]
        high_issues = [r for r in self.results if not r.passed and r.severity == "high"]
        medium_issues = [r for r in self.results if not r.passed and r.severity == "medium"]
        low_issues = [r for r in self.results if not r.passed and r.severity == "low"]

        return {
            "summary": {
                "total_tests": len(self.results),
                "passed": passed,
                "failed": failed,
                "success_rate": f"{(passed / len(self.results) * 100):.1f}%" if self.results else "0%",
            },
            "issues": {
                "critical": len(critical_issues),
                "high": len(high_issues),
                "medium": len(medium_issues),
                "low": len(low_issues),
            },
            "results": [r.to_dict() for r in self.results],
            "recommendations": self._generate_recommendations(),
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on test results."""
        recommendations = []

        for result in self.results:
            if not result.passed:
                if result.severity == "critical":
                    recommendations.append(f"🔴 CRITICAL: {result.message}")
                elif result.severity == "high":
                    recommendations.append(f"🟠 HIGH: {result.message}")
                elif result.severity == "medium":
                    recommendations.append(f"🟡 MEDIUM: {result.message}")
                else:
                    recommendations.append(f"🟢 LOW: {result.message}")

        return recommendations


def main():
    """Main entry point for security testing."""
    tester = SecurityTester()
    results = tester.run_all_tests()

    print("\n" + "="*60)
    print("📊 SECURITY TEST SUMMARY")
    print("="*60)

    report = tester.generate_report()

    print(f"\nTotal Tests: {report['summary']['total_tests']}")
    print(f"Passed: {report['summary']['passed']}")
    print(f"Failed: {report['summary']['failed']}")
    print(f"Success Rate: {report['summary']['success_rate']}")

    print(f"\n🔴 Critical Issues: {report['issues']['critical']}")
    print(f"🟠 High Issues: {report['issues']['high']}")
    print(f"🟡 Medium Issues: {report['issues']['medium']}")
    print(f"🟢 Low Issues: {report['issues']['low']}")

    if report['recommendations']:
        print("\n📋 RECOMMENDATIONS:")
        for rec in report['recommendations']:
            print(f"  {rec}")

    # Save report to file
    report_file = Path("security_test_report.json")
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n📄 Detailed report saved to: {report_file}")

    # Exit with error code if critical issues found
    if report['issues']['critical'] > 0:
        print("\n❌ CRITICAL security issues found - please address before deployment!")
        sys.exit(1)
    elif report['issues']['high'] > 0:
        print("\n⚠️  HIGH priority security issues found - address before production deployment!")
        sys.exit(1)
    else:
        print("\n✅ No critical or high security issues found!")
        sys.exit(0)


if __name__ == "__main__":
    main()