from safety_schemas.models.events.payloads import InitExitStep


class StepTracker:
    def __init__(self):
        self.current_step: InitExitStep = InitExitStep.UNKNOWN
