import json
from datetime import datetime
from pathlib import Path
import structlog
from jinja2 import Template

logger = structlog.get_logger()

class RedTeamReportGenerator:
    """Generate professional red team audit reports"""

    def __init__(self):
        self.template = self._load_template()

    def _load_template(self) -> str:
        """Load HTML report template"""
        return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Red Team LLM Audit Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }

        .header {
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
            padding: 40px;
            border-radius: 8px;
            margin-bottom: 30px;
        }

        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }

        .executive-summary {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            border-left: 4px solid #e74c3c;
        }

        .score-box {
            display: flex;
            justify-content: space-around;
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }

        .score-item { text-align: center; }
        .score-value { font-size: 3em; font-weight: bold; color: #e74c3c; }
        .score-label { color: #666; margin-top: 10px; }

        .attack-result {
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            border-left: 4px solid #e74c3c;
        }

        .attack-result.vulnerable {
            border-left-color: #c0392b;
            background-color: #fff5f5;
        }

        .attack-result.safe {
            border-left-color: #27ae60;
            background-color: #f5fff5;
        }

        .severity-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }

        .severity-badge.CRITICAL { background-color: #c0392b; }
        .severity-badge.HIGH { background-color: #e74c3c; }
        .severity-badge.MEDIUM { background-color: #f39c12; }
        .severity-badge.LOW { background-color: #3498db; }
        .severity-badge.INFO { background-color: #95a5a6; }

        .attack-result h3 { margin: 0 0 10px 0; }
        
        .code-block {
            background: #f4f4f4;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            overflow-x: auto;
            font-family: monospace;
            font-size: 0.9em;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }

        .stat-card h3 { margin: 0; color: #666; font-size: 0.9em; }
        .stat-card .value { font-size: 2.5em; font-weight: bold; color: #e74c3c; margin: 10px 0; }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: white;
        }

        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f5f5f5; font-weight: bold; }

        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
            border-top: 1px solid #ddd;
        }

        .attack-type-section {
            margin-bottom: 30px;
        }

        .attack-type-section h2 {
            border-bottom: 2px solid #e74c3c;
            padding-bottom: 10px;
            color: #c0392b;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Red Team LLM Audit Report</h1>
        <p>Model: {{ model_name }}</p>
        <p>Audit Date: {{ audit_date }}</p>
    </div>

    <div class="executive-summary">
        <h2>Executive Summary</h2>
        <p>This report presents findings from a comprehensive red team assessment of the <strong>{{ model_name }}</strong> language model. The assessment executed {{ total_attacks }} adversarial attacks across three categories: prompt injection, jailbreak attempts, and data extraction.</p>
        <p><strong>Total Attacks Executed:</strong> {{ total_attacks }}</p>
        <p><strong>Successful Attacks:</strong> {{ successful_attacks }}</p>
        <p><strong>Success Rate:</strong> {{ success_rate }}%</p>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <h3>Total Attacks</h3>
            <div class="value">{{ total_attacks }}</div>
        </div>
        <div class="stat-card">
            <h3>Successful</h3>
            <div class="value">{{ successful_attacks }}</div>
        </div>
        <div class="stat-card">
            <h3>Success Rate</h3>
            <div class="value">{{ "%.1f" % success_rate }}%</div>
        </div>
    </div>

    <h2>Attack Results by Category</h2>

    {% for category, attacks in attacks_by_type.items() %}
    <div class="attack-type-section">
        <h2>{{ category | title }} Attacks</h2>
        <p>{{ attacks | length }} attacks executed in this category</p>
        
        {% for attack in attacks %}
        <div class="attack-result {% if attack.vulnerable %}vulnerable{% else %}safe{% endif %}">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h3>{{ attack.attack_name }}</h3>
                <span class="severity-badge {{ attack.severity }}">{{ attack.severity }}</span>
            </div>

            <p><strong>Status:</strong> {% if attack.vulnerable %}<span style="color: #c0392b; font-weight: bold;">VULNERABLE</span>{% else %}<span style="color: #27ae60; font-weight: bold;">SAFE</span>{% endif %}</p>
            <p><strong>Confidence:</strong> {{ "%.1f" % (attack.confidence * 100) }}%</p>

            <div><strong>Attack Payload:</strong>
                <div class="code-block">{{ attack.payload }}</div>
            </div>

            <p><strong>Model Response (Preview):</strong></p>
            <div class="code-block">{{ attack.response_preview }}</div>
        </div>
        {% endfor %}
    </div>
    {% endfor %}

    <h2>Summary</h2>
    <table>
        <tr>
            <th>Metric</th>
            <th>Value</th>
        </tr>
        <tr>
            <td>Total Attacks</td>
            <td>{{ total_attacks }}</td>
        </tr>
        <tr>
            <td>Successful Attacks</td>
            <td>{{ successful_attacks }}</td>
        </tr>
        <tr>
            <td>Success Rate</td>
            <td>{{ "%.1f" % success_rate }}%</td>
        </tr>
        <tr>
            <td>Model Tested</td>
            <td>{{ model_name }}</td>
        </tr>
    </table>

    <h2>Recommendations</h2>
    <ol>
        <li><strong>System Prompt Hardening:</strong> Strengthen system instructions to resist jailbreak attempts</li>
        <li><strong>Input Validation:</strong> Implement robust input filtering for malicious payloads</li>
        <li><strong>Output Monitoring:</strong> Monitor model outputs for signs of successful attacks</li>
        <li><strong>Rate Limiting:</strong> Implement rate limits to prevent brute force attacks</li>
        <li><strong>Continuous Testing:</strong> Perform regular red team assessments to identify new vulnerabilities</li>
    </ol>

    <div class="footer">
        <p>Generated by Red Team LLM Toolkit</p>
        <p>{{ generated_date }}</p>
    </div>
</body>
</html>
        """

    def generate_html_report(self, audit_result, output_path: str) -> str:
        """Generate HTML report from RedTeamAuditResult"""
        logger.info("Generating red team HTML report", output_path=output_path)

        # Group attacks by type
        attacks_by_type = {}
        for attack in audit_result.attack_results:
            attack_type = attack.attack_type
            if attack_type not in attacks_by_type:
                attacks_by_type[attack_type] = []
            attacks_by_type[attack_type].append({
                "attack_name": attack.attack_name,
                "attack_type": attack.attack_type,
                "payload": attack.payload,
                "vulnerable": attack.vulnerable,
                "confidence": attack.confidence,
                "response_preview": attack.response_preview,
                "severity": attack.severity
            })

        template = Template(self.template)
        html_content = template.render(
            model_name=audit_result.model_name,
            audit_date=audit_result.timestamp,
            total_attacks=audit_result.total_attacks,
            successful_attacks=audit_result.successful_attacks,
            success_rate=audit_result.success_rate,
            attacks_by_type=attacks_by_type,
            generated_date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        )

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info("Red team report generated", output_path=output_path)
        return output_path

    def generate_json_report(self, audit_result, output_path: str) -> str:
        """Generate JSON report from RedTeamAuditResult"""
        logger.info("Generating red team JSON report", output_path=output_path)

        report_data = {
            "model_name": audit_result.model_name,
            "audit_timestamp": audit_result.timestamp,
            "total_attacks": audit_result.total_attacks,
            "successful_attacks": audit_result.successful_attacks,
            "success_rate": audit_result.success_rate,
            "attack_results": [
                {
                    "attack_name": attack.attack_name,
                    "attack_type": attack.attack_type,
                    "payload": attack.payload,
                    "vulnerable": attack.vulnerable,
                    "confidence": attack.confidence,
                    "severity": attack.severity
                }
                for attack in audit_result.attack_results
            ]
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)

        logger.info("Red team JSON report generated", output_path=output_path)
        return output_path