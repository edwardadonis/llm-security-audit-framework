import asyncio
import os
from dotenv import load_dotenv
import structlog
from src.red_team.red_team_auditor import RedTeamAuditor
from src.reports.red_team_report_generator import RedTeamReportGenerator

load_dotenv()

logger = structlog.get_logger()

async def main():
    """Main execution for red team auditing"""
    print("\n Red Team LLM Toolkit\n")
    print("=" * 50)

    print("\nWhich model would you like to red team?")
    print("1. GPT-3.5-turbo (requires OpenAI API key)")
    print("2. Claude (requires Anthropic API key)")
    choice = input("\nEnter choice (1 or 2): ").strip()

    if choice == "1":
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key or api_key == "your_openai_key_here":
            print("\nOpenAI API key not configured in .env file")
            print("Please add your key to .env:")
            print("OPENAI_API_KEY=sk-...")
            return

        print("\nStarting GPT-3.5-turbo red team audit...")
        auditor = RedTeamAuditor(
            model_name="gpt-3.5-turbo",
            api_key=api_key,
            model_type="openai"
        )
        report_name = "gpt-3.5-turbo_red_team"

    elif choice == "2":
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key or api_key == "your_anthropic_key_here":
            print("\nAnthropic API key not configured in .env file")
            print("Please add your key to .env:")
            print("ANTHROPIC_API_KEY=sk-ant-...")
            return

        print("\nStarting Claude red team audit...")
        auditor = RedTeamAuditor(
            model_name="claude-3-opus-20240229",
            api_key=api_key,
            model_type="anthropic"
        )
        report_name = "claude_red_team"

    else:
        print("Invalid choice")
        return

    try:
        results = await auditor.run_full_red_team()

        print("\n" + "=" * 50)
        print("RED TEAM AUDIT COMPLETE\n")
        print(f"Model: {results.model_name}")
        print(f"Total Attacks: {results.total_attacks}")
        print(f"Successful Attacks: {results.successful_attacks}")
        print(f"Success Rate: {results.success_rate:.1f}%")
        print("=" * 50 + "\n")

        # Generate reports
        report_generator = RedTeamReportGenerator()
        
        html_path = f"data/red_team_reports/{report_name}_audit.html"
        json_path = f"data/red_team_reports/{report_name}_audit.json"
        
        report_generator.generate_html_report(results, html_path)
        report_generator.generate_json_report(results, json_path)
        
        print(f"\n✓ HTML Report: {html_path}")
        print(f"✓ JSON Report: {json_path}\n")

    except Exception as e:
        print(f"\nError during red team audit: {str(e)}")
        print("\nMake sure:")
        print("1. You have valid API keys in .env")
        print("2. You have internet connection")
        print("3. API services are online")

if __name__ == "__main__":
    print("Starting Red Team LLM Toolkit...")
    asyncio.run(main())