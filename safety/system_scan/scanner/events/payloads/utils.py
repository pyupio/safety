def required(name: str):
    def _raise():
        raise TypeError(f"Missing required argument: {name}")

    return _raise
