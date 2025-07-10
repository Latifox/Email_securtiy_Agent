FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    libglib2.0-0 \
    libgtk-3-0 \
    libmagic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Google Cloud CLI
RUN curl https://sdk.cloud.google.com | bash
ENV PATH $PATH:/root/google-cloud-sdk/bin

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package
RUN pip install -e .

# Expose port
EXPOSE 8080

# Environment variables
ENV GOOGLE_GENAI_USE_VERTEXAI=true
ENV PORT=8080

# Run the application
CMD ["adk", "web", "--host", "0.0.0.0", "--port", "8080"] 