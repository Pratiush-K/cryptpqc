"""Mosca's inequality: are you already exposed to harvest-now-decrypt-later?"""
from dataclasses import dataclass


@dataclass(frozen=True)
class MoscaResult:
	shelf_life: float
	migration_time: float
	years_to_threat: float
	exposure_years: float
	exposed: bool
	verdict: str


def mosca(shelf_life: float, migration_time: float, years_to_threat: float) -> MoscaResult:
	"""Exposed when shelf_life + migration_time > years_to_threat (all in years)."""
	if min(shelf_life, migration_time, years_to_threat) < 0:
		raise ValueError("All inputs must be zero or positive")
	exposure = shelf_life + migration_time - years_to_threat
	exposed = exposure > 0
	if exposed:
		verdict = (
			f"EXPOSED: your data must stay secret {exposure:.1f} year(s) longer than "
			"the time you have. Start migrating now."
		)
	else:
		verdict = (
			f"OK for now: you have {-exposure:.1f} year(s) of margin, "
			"but migration takes time, so plan it."
		)
	return MoscaResult(shelf_life, migration_time, years_to_threat, exposure, exposed, verdict)
