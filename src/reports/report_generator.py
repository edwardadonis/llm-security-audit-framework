# src/reports/report_generator.py

import json
from datetime import datetime
from pathlib import Path
import structlog
from jinja2 import Template

logger = structlog.get_logger()

class ReportGenerator:
    """Generate professional security audit reports"""

    def _init_(self):
        self.template = self._load_template()

    def _load_template(self) -> str:
        """Load HTML report template"""
        return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LLM Security Audit Report</title>
    <style>
        body {
            font-family: 'Segoe UI' , Tahoma, Geneva, Verana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background-color: f5f5f5;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 8px;
            margin-bottom: 30px;
        }

        .header h1 { margin: 0; font-size: 2.5em; }
        .header p {margin: 10px 0 0 0 ; opacity: 0.9: }

        .executive-summary {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            border-left: 4px solid #667eea;
        }

        .score-box {
            display: flex;
            justify-content: space-around;
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom; 30px;
        }

        .score_item { text-align: center; }
        .score_value {font-size: 3em; font_weight; bold; color; #667eea;
        .score_label {color: #666; margin-top: 10px; }

        .vulnerability {
            backgroun: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
        }

        .severity-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }

        .severity-badge.CRITICAL { background-colour: #c0392b; }
        .severity-badge.HIGH { background-colour: #e74c3c; }
        .severtiy-badge.MEDIUM { background-colouur: #f39c12; }
        .severity-badge.LOW { background-color: #3498db; }

        .vulnerability h3 {margin: 0 0 10px 0; }
        .code-block {
            background: #f4f4f4;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            overflow-x: auto;
            font-family: monospace;
        }

        .recommendation {
            background: #e8f4f8;
            padding: 15px;
            border-radius: 4px;
            margin: 15px 0;
            border-left: 4px solid #3498db;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
        }

        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: "#f5f5f5; font-weight: bold; }

        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
            border-top: 1px solid #ddd;
        }
    </style>
</head>
</head>
<body>
    <div class="header">
        <h1>LLM Security Audit Report<h1>
        <p>ModelL {{ model_name }}</p>
        <p>Audit Date: {{ audit_date }}</p>
    </div>

    <div class="executive-summary">
        <h2>/Executive Summary</h2>
        <p>This report presennts findings from a comprehensive security audit of the <strong>{{ model_name }}</strong> language model. The audit examined the model for common vulnerabilities including prompt injection, jailbreak attempts. and data leakage.</p>
        <p><strong>Total Vulnerabilities Found:</strong> {{ vulnerability_count }}</p>
        <p><strong>Critical Issues:</strong> {{ critical_count }}</p>
        <p><stong>High Priority Issues:</strong> {{ high_count }}</P>
    </div>

    <div class="score-box">
        <div class="score-item">
            <div class="score-value">{{ security_score }}</div>
            <div class="score-label">Security Score</div>
        </div>
        <div class="score-item">
            <div class="score-value">{{ total_tests }}</div>
            <div class=""score-label">Test Run</div>
        </div>
        <div class="score-item">
            <div class="score-value">{{ failure_rate }}%</div>
            <div class="score_lable"Failure Rate"</div>
        <div>
    </div>

    <h2>Detailed Findings</h2>

    {% if vulnerabilities %}
        {% for vuln in vulnerabilities %}
        <div class="vulnerability">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h3>{{ vuln.title }}<h3>
                <span class="severity-badge {{ vuln.severity }}">{{ vuln.severity }}</span>
            </div>

            <p><strong>Type:</strong> {{ vuln.type }}</p>
            <p><strong>Desctiption:</strong> {{ vuln.description }}</p>

            <div><strong>Test Payload:</strong>
                <div class="code-block">{{ vuln.test_payload }}</div>
            </div>

            <p><strong>Confidence:</strong>  {{ "%.1f" % (vuln.confidence *100 ) }}%</p>

            <div class="recommendation">
                <strong>Recommendation:</strong> {{ vuln.recommendation}}
            </div>
        </div>
        {% endfor %}
    {% else %}
        <div style="background: white; padding: 20px; border-radius: margin-bottom: 20px;">
            <p> No vulnerabilities found during this audit.</p>
        </div>
    {% endif %}

    <h2>Recommendations</h2>

    <ol>
        <li><strong>Input Validation:</strong> Implement robust input validation and sanitization</li>
        <li><strong>Output Filtering:</strong> Add output filtering to prevent disclosure</li>
        <li><strong>System Prompt Hardening:</strong> Strengthen system prompts against manupilation</li>
        <li><strong>Rate Limiting:</strong> Implement rate limiting to prevent abuse</li>
        <li><strong>Monitoring:</strong> Set up continues monitoring and logging</li>
    <ol>

    <div class="footer">
        <p>Generated by LLM Security Audit Framework</p>
        <p>{{ generated_date }}</p>
    </div>
</body>
</html>
        """

    def generate_html_report(self, audit_result, output_path: str) -> str:
        """Generate HTML report"""
        logger.info("Generating HTML report", output_path=output_path)

        critical_count = sum(1 for v in audit_result.vulnerabilities
                            if v.severity == "CRITICAL")
        high_count = sum(1 for v in audit_result.vulnerabilities
                            if v.severity == "HIGH")

        total_tests = sum(audit_result.tests_run.values())
        failure_rate = round((len(audit_result.vulnerabilities) / total_tests * 100) if total_tests > 0 else 0 )

        template = Template(self.template)
        html_content = template.render(
            model_name=audit_result.model_name,
            audit_date=audit_result.audit_timestamp,
            security_score=int(audit_result.overall_security_score),
            vulnerability_count=len(audit_result.vulnerabilities),
            critical_count=critical_count,
            high_count=high_count,
            total_tests=total_tests,
            failure_rate=failure_rate,
            vulnerabilities=audit_result.vulnerabilities,
            generated_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        )

        Path_(output_path).parent.mkdir(parents=True, exists_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info("Report generated", output_path=output_path)
        return output_path

    def generate_json_report(self, audit_result, output_path: str) -> str:
        """Generate JSON report"""
        logger.info("Generate JSON report", output_path=output_path)

        report_data = {
            "model_name": audit_result.model_name,
            "audit_timestamp": audit_result.audit_timestamp,
            "security_score": audit_result.overall_security_score,
            "total_vulnerabilities": len(audit_result.vulnerabilities),
            "vulnerabilities": [
                {
                    "id": v.id,
                    "type": v.type,
                    "severity": v.severity,
                    "confidence": v.confidence
                }
                for v in audit_result.vulnerabilities
            ]
        }

        Path(output_path).parent.mkdir(parens=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)

        logger.info("JSON report generated", output_path=output_path)
        return output_pathS