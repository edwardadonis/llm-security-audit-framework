import asyncio
import os
from dotenv import load_dotenv
import structlog
from src.auditor import LLMAuditor
from src.reports.report_generator import ReportGenerator

load_dotenv()

logger = structlog.get_logger()
async def main():
    """Main execution"""
    print("\n LLM Security Audit Framework\n")
    print("=" * 50)

    # Get model choice
    print("\nWhich model would you like to audit?")
    print("1. GPT-4 (requires OpenAPI key)")
    print("2. Claude (requires Anthropic API key)")
    choice = input("\nEnter choice (  or 2)").strip()

    if choice == "1":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key or api_key == "your_openapi_key_here":
            print("/n OpenAI API key not configured in .env file")
            print("please add your key to .env:")
            print(" OPENAI_API_KEY=sk-...")
            return

        print("\n starting GPT-4 audit...")
        auditor = LLMAuditor(
            model_name="gpt-4",
            api_key=api_key,
            model_type="openai"
        )
        report_name = "gpt4_audit"

    elif choice == "2":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key or api_key == "your_anthropic_key_here":
            print("\n Anthropic API key not configured in .env file")
            print("Please add your key to .env:")
            print( " ANTHROPIC_API_KEY=sk-ant-...")
            return

        print("\n Starting Claude audit...")
        auditor = LLMAudditor(
            model_name="claude-3-opus-20240229",
            api_key=api_key,
            model_type="anthropic"
        )
        report_name = "claude_audit"

    else:
        print("invalid choice")
        return

    try:
        # Run audit
        results = await auditor.run_full_audit()

        # Generate reports
        report_gen = reportGenerator()


        html_path = report_gen.generate_html_report(
            results,
            output_path=f"data/sample_reports/{report_name}.json"
        )

        #Print results
        print("\n" + "=" * 50)
        print(" AUDIT COMPLETE\n")
        print(f"Model: {results.model_name}")
        print(f"Security Score: {int(results.overall_security_score)}/100")
        print(f"vulnerabilities Found: {len(results.vulnerabilities)}")
        print(f"\nReports:")
        print(f" HTML: {html_path}")
        print(f" JSON: {json_path}")
        print("=" * 50 + "\n")

    except Exception as e:
        print(f"\n Error during audit: {str(e)}")
        print("\nMake sure:")
        print(" 1. You have valid API keys in .env")
        print(" 2. You have internet connection")
        print(" 3. API services are online")

if __name__ == "__main__":
    print("Starting LLM Security Audit Framework...")
    asyncio.run(main())
