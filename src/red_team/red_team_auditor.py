from typing import List, Dict, Optional
from dataclasses import dataclass, field
import asyncio
import structlog
from datetime import datetime

logger = structlog.get_logger()

@dataclass
class AttackResult:
    attack_name: str
    attack_type: str
    payload: str
    vulnerable: bool
    confidence: float
    response_preview: str
    severity: str

@dataclass
class RedTeamAuditResult:
    model_name: str
    timestamp: str
    total_attacks: int
    successful_attacks: int
    attack_results: List[AttackResult] = field(default_factory=list)
    success_rate: float = 0.0

class RedTeamAuditor:
    def __init__(self, model_name: str, api_key: str, model_type: str = "openai"):
        self.model_name = model_name
        self.api_key = api_key
        self.model_type = model_type
        self.attack_results: List[AttackResult] = []
        self.client = None

    async def initialize_client(self):
        if self.model_type == "openai":
            from openai import AsyncOpenAI
            self.client = AsyncOpenAI(api_key=self.api_key)
        elif self.model_type == "anthropic":
            from anthropic import AsyncAnthropic
            self.client = AsyncAnthropic(api_key=self.api_key)

    async def query_model(self, prompt: str, temperature: float = 0.7) -> str:
        try:
            if self.model_type == "openai":
                response = await self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=temperature,
                    max_tokens=500,
                )
                return response.choices[0].message.content
        except Exception as e:
            logger.error("Error querying model", error=str(e))
            raise

    async def run_full_red_team(self) -> RedTeamAuditResult:
        await self.initialize_client()
        logger.info("Starting red team audit", model=self.model_name)

        try:
            from src.red_team.modules.injection_attacks import InjectionAttacker
            from src.red_team.modules.jailbreak_attacks import JailbreakAttacker
            from src.red_team.modules.extraction_attacks import ExtractionAttacker

            Injector = InjectionAttacker(self)
            await Injector.run_injection_attacks()

            jailbreaker = JailbreakAttacker(self)
            await jailbreaker.run_jailbreak_attacks()

            extractor = ExtractionAttacker(self)
            await extractor.run_extraction_attacks()

        except Exception as e:
            logger.error("Error during red team audit", error=str(e))

        return self._compile_results()

    def add_attack_result(self, result: AttackResult):
        self.attack_results.append(result)

    def _compile_results(self) -> RedTeamAuditResult:
        successful = sum(1 for r in self.attack_results if r.vulnerable)
        total = len(self.attack_results)
        success_rate = (successful / total * 100) if total > 0 else 0

        return RedTeamAuditResult(
            model_name=self.model_name,
            timestamp=datetime.now().isoformat(),
            total_attacks=total,
            successful_attacks=successful,
            attack_results=self.attack_results,
            success_rate=success_rate

        )