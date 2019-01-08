FROM python:3.6-slim
RUN pip install --trusted-host pypi.python.org safety
CMD ["python"]
