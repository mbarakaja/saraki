FROM python:3.8-alpine

ARG VERSION=${VERSION:-"master"}
ARG GIT_REMOTE_URL=${GIT_REMOTE_URL:-"https://github.com/mbarakaja/saraki"}

WORKDIR /opt/app

# Install Python and external dependencies, including headers and GCC
# RUN apk add --no-cache python3 python3-dev py3-pip libffi libffi-dev musl-dev gcc git ca-certificates openblas-dev musl-dev g++
RUN apk add --no-cache musl-dev gcc git ca-certificates

# Install Pipenv
RUN pip3 install pipenv

# Create a virtual environment and activate it
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
	VIRTUAL_ENV="/opt/venv"

# Install dependencies into the virtual environment with Pipenv
RUN git clone --depth=1 -b ${VERSION} ${GIT_REMOTE_URL} /opt/app \
	&& cd /opt/app \
	&& python3 -m pip install --upgrade pip \
	&& pip3 install .

FROM python:3.8-alpine
MAINTAINER Luc Michalski <michalski.luc@gmail.com>

ARG VERSION=${VERSION:-"master"}
ARG GIT_URL=${SARAKI_GIT_URL:-"https://github.com/mbarakaja/saraki"}
ARG BUILD
ARG NOW

# Create runtime user
RUN mkdir -p /opt \
	&& adduser -D saraki -h /opt/app -s /bin/sh \
 	&& su saraki -c 'cd /opt/app; mkdir -p data config'

# Install Python and external runtime dependencies only
# RUN apk add --no-cache python3 libffi openblas libstdc++

# Switch to user context
USER saraki
WORKDIR /opt/saraki/data

# Copy the virtual environment from the previous image
COPY --from=build /opt/venv /opt/venv

# Activate the virtual environment
ENV PATH="/opt/venv/bin:$PATH" \
	VIRTUAL_ENV="/opt/venv"

LABEL name="saraki" \
      version="$VERSION" \
      build="$BUILD" \
      architecture="x86_64" \
      build_date="$NOW" \
      vendor="twintproject" \
      maintainer="x0rzkov <michalski.luc@gmail.com>" \
      url="${GIT_URL}" \
      summary="Dockerized version of Saraki project" \
      description="Dockerized version of Saraki project" \
      vcs-type="git" \
      vcs-url="${GIT_URL}" \
      vcs-ref="$VERSION" \
      distribution-scope="public"

ENTRYPOINT ["python3", "app.py"]
