FROM ubuntu:20.04

# Install necessary packages
RUN apt-get update && apt-get install -y \
    bpfcc-tools \
    linux-headers-generic \
    clang \
    llvm \
    iproute2 \
    python3-pip \
    kmod

# Install Python packages
RUN pip3 install bcc pyroute2

# Copy your script into the container
COPY script.py /root/

# Set the working directory
WORKDIR /root

# Run your script
CMD ["python3", "script.py"]