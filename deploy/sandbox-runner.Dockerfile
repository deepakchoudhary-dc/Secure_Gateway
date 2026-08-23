# Minimal hardened sandbox runner for production code execution.
# Build:  docker build -t ai-sandbox-runner -f deploy/sandbox-runner.Dockerfile .
# Run (set SANDBOX_RUNNER_COMMAND so the gateway invokes it per execution):
#   docker run --rm --network none --memory 256m --cpus 0.5 --read-only \
#     -v <host-script-dir>:/sandbox:ro ai-sandbox-runner /sandbox/sandbox_run.py
FROM python:3.12-slim

RUN useradd --create-home runner
USER runner
WORKDIR /home/runner
COPY src/sandbox/sandbox_wrapper.py /home/runner/sandbox_wrapper.py
ENTRYPOINT ["python", "/home/runner/sandbox_wrapper.py"]
