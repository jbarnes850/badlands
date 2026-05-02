from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from badlands.agents.llm import GreenUserLLM, LLMDecision


class UserSimulator(Protocol):
    def decide(self, observation: dict) -> LLMDecision: ...


@dataclass
class CachedReplayUserSimulator:
    cache_dir: Path
    seed: int = 1

    def __post_init__(self) -> None:
        self.actor = GreenUserLLM(cache_dir=self.cache_dir, seed=self.seed)

    def decide(self, observation: dict) -> LLMDecision:
        return self.actor.decide(observation)
