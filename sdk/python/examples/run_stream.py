from aegis import AegisClient, DoneEvent, ErrorEvent, ProofEvent, StdoutEvent

client = AegisClient()
for event in client.stream(language="bash", code="echo streamed"):
    if isinstance(event, StdoutEvent):
        print(event.chunk, end="")
    elif isinstance(event, ProofEvent):
        print(f"receipt_path={event.proof_bundle.receipt_path}")
    elif isinstance(event, DoneEvent):
        print(f"done exit={event.exit_code} duration_ms={event.duration_ms}")
    elif isinstance(event, ErrorEvent):
        print(f"stream error: {event.error}")
