# Acadia-Configuration — Docker build/run helpers.
#
# Builds the production webconfigd container image. Uses buildx for cross-platform
# support but defaults to the host architecture for a fast local build.

IMAGE_NAME ?= acadia-webconfigd
TAG        ?= latest
IMAGE      := $(IMAGE_NAME):$(TAG)

.PHONY: build run stop logs clean shell push

build:
	@echo "Building Docker image $(IMAGE) ..."
	docker build -f Dockerfile -t $(IMAGE) ..

# Cross-arch (e.g. build the arm64 image on an x86 host). Requires buildx + a
# builder with the target platform driver enabled.
build-arm64:
	docker buildx build --platform linux/arm64 --load -f Dockerfile -t $(IMAGE)-arm64 ..

run:
	@echo "Running $(IMAGE) (port 8443) ..."
	docker run --rm -d --name webconfigd \
		-p 8443:8443 \
		-v webconfig-data:/data \
		$(IMAGE)

stop:
	docker stop webconfigd 2>/dev/null || true

logs:
	docker logs -f webconfigd

clean:
	docker rmi $(IMAGE) 2>/dev/null || true

shell:
	docker run --rm -it --entrypoint /bin/sh $(IMAGE)

# Push to a registry (set REGISTRY to push elsewhere).
push:
	docker tag $(IMAGE) $(REGISTRY)/$(IMAGE)
	docker push $(REGISTRY)/$(IMAGE)
