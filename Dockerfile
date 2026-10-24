# =============================================================================
# Hardened by BreachBench + OCI Community Container Hardening Work Bench
# Original Base Image: ubuntu:24.04 -> Hardened Runtime: scratch (non-root 53111:53111)
# =============================================================================
FROM base-${TARGETARCH} AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    DEBCONF_NONINTERACTIVE_SEEN=true \
    UCF_FORCE_CONFFNEW=1

# Create minimal distroless-style rootfs hierarchy
RUN mkdir -p /rootfs/etc/ssl/certs /rootfs/usr/share /rootfs/lib /rootfs/usr/lib \
             /rootfs/usr/local/bin /rootfs/usr/local/lib /rootfs/usr/bin /rootfs/bin \
             /rootfs/tmp /rootfs/var /rootfs/home/nonroot && \
    chmod 1777 /rootfs/tmp

# Install required packages + dependency resolver for minimal rootfs extraction
RUN apt-get update && \
    apt-get install -y --no-install-recommends apt-rdepends ca-certificates ca-certificates libvulkan1 libopenblas0 && \
    dpkg-architecture -qDEB_HOST_MULTIARCH > /tmp/multiarch.txt && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Execute upstream application build and asset steps inside builder stage
WORKDIR /go/src/github.com/ollama/ollama
COPY --from=image-archive /bin /usr/bin
COPY --from=image-archive /lib/ollama /usr/lib/ollama
cmake -S llama/server --preset cpu && cmake --build build/llama-server-cpu -- -l $(nproc) && cmake --install build/llama-server-cpu --component llama-server --strip
cmake -S llama/server --preset llama_cuda_v12_linux && cmake --build build/llama-server-cuda_v12 -- -l $(nproc) && cmake --install build/llama-server-cuda_v12 --component llama-server --strip
cmake -S llama/server --preset llama_cuda_v13_linux && cmake --build build/llama-server-cuda_v13 -- -l $(nproc) && cmake --install build/llama-server-cuda_v13 --component llama-server --strip
cmake -S llama/server --preset rocm_v7_2_linux && cmake --build build/llama-server-rocm_v7_2 -- -l $(nproc) && cmake --install build/llama-server-rocm_v7_2 --component llama-server --strip
cmake -S llama/server --preset vulkan && cmake --build build/llama-server-vulkan -- -l $(nproc) && cmake --install build/llama-server-vulkan --component llama-server --strip
cmake -S . -B build/mlx_cuda_v13 -DOLLAMA_MLX_BACKENDS=cuda_v13 -DBLAS_INCLUDE_DIRS=/usr/include/openblas -DLAPACK_INCLUDE_DIRS=/usr/include/openblas -DCMAKE_CUDA_FLAGS="-t ${OLLAMA_MLX_NVCC_THREADS}" ${MLX_CUDA_RAM_MB:+-DMLX_CUDA_RAM_MB=${MLX_CUDA_RAM_MB}} -DOLLAMA_PAYLOAD_INSTALL_PREFIX=/go/src/github.com/ollama/ollama/dist && cmake --build build/mlx_cuda_v13 --target ollama-mlx-cuda_v13 -- -l $(nproc) ${OLLAMA_MLX_BUILD_JOBS:+-j ${OLLAMA_MLX_BUILD_JOBS}}
go build -trimpath -buildmode=pie -o /bin/ollama .
cmake -S . -B build/go-license -DOLLAMA_LLAMA_BACKENDS= -DOLLAMA_MLX_BACKENDS= && cmake --build build/go-license --target ollama-go-license

# Extract required package binaries, compiled app artifacts, and ldd-verified shared libraries into /rootfs
RUN set -eux; \
    for pkg in ca-certificates libvulkan1 libopenblas0; do \
        dpkg -L "$pkg" 2>/dev/null || true; \
    done | sort -u > /tmp/package-files.txt; \
    find /usr/local/bin /usr/local/sbin /usr/local/lib -type f -o -type l 2>/dev/null >> /tmp/package-files.txt || true; \
    if [ -d "/go/src/github.com/ollama/ollama" ] && [ "/go/src/github.com/ollama/ollama" != "/home/nonroot" ]; then \
        mkdir -p "/rootfs/go/src/github.com/ollama/ollama" && cp -a "/go/src/github.com/ollama/ollama/." "/rootfs/go/src/github.com/ollama/ollama/" || true; \
        find "/go/src/github.com/ollama/ollama" -type f -executable 2>/dev/null >> /tmp/package-files.txt || true; \
    fi; \
    while IFS= read -r file; do \
        if [ -e "$file" ] && [ ! -d "$file" ]; then \
            case "$file" in \
                /usr/local/bin/*|/usr/local/sbin/*|/usr/local/lib/*|/usr/bin/*|/bin/*|/usr/sbin/*|/sbin/*|/usr/lib/*.so*|/lib/*.so*|/etc/*.conf) \
                    mkdir -p "/rootfs$(dirname "$file")" && cp -a "$file" "/rootfs$file" || true ;; \
            esac; \
            if [ -x "$file" ]; then \
                ldd "$file" 2>/dev/null | awk '/=>/ {print $3}' | while read -r lib; do \
                    if [ -n "$lib" ] && [ -f "$lib" ]; then \
                        mkdir -p "/rootfs$(dirname "$lib")" && cp -Ln "$lib" "/rootfs$lib" || true; \
                    fi; \
                done; \
            fi; \
        fi; \
    done < /tmp/package-files.txt; \
    MULTIARCH=$(cat /tmp/multiarch.txt); \
    find /lib/$MULTIARCH /lib /lib64 -name 'ld-linux*.so.*' -o -name 'libc.so.*' 2>/dev/null | while read -r rt; do \
        mkdir -p "/rootfs$(dirname "$rt")" && cp -Ln "$rt" "/rootfs$rt" || true; \
    done; \
    cp -a /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ 2>/dev/null || true

# Configure unprivileged nonroot user (UID/GID 53111) and strip interactive login shell
RUN echo 'nonroot:x:53111:53111:nonroot:/home/nonroot:/sbin/nologin' > /rootfs/etc/passwd && \
    echo 'nonroot:x:53111:' > /rootfs/etc/group && \
    chown -R 53111:53111 /rootfs/home/nonroot

# Generate embedded CycloneDX 1.5 SBOM (/rootfs/sbom.json)
RUN cat > /usr/local/bin/generate_sbom <<'SCRIPT_EOF'
#!/usr/bin/env bash
set -euo pipefail
root_packages=(
    "ca-certificates"
    "libvulkan1"
    "libopenblas0"
)
echo '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":['
for i in "${!root_packages[@]}"; do
  pkg="${root_packages[$i]}"
  ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo 'unknown')
  sep=$([ $i -lt $((${#root_packages[@]}-1)) ] && echo ',' || echo '')
  echo "  {\"type\":\"library\",\"name\":\"$pkg\",\"version\":\"$ver\"}$sep"
done
echo ']}'
SCRIPT_EOF
RUN chmod +x /usr/local/bin/generate_sbom && /usr/local/bin/generate_sbom > /rootfs/sbom.json

# =============================================================================
# Final Hardened Runtime Stage (Zero-OS Scratch Image)
# =============================================================================
FROM scratch

COPY --from=builder --chown=53111:53111 /rootfs/ /
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LD_LIBRARY_PATH=/usr/local/nvidia/lib:/usr/local/nvidia/lib64
ENV NVIDIA_DRIVER_CAPABILITIES=compute,utility
ENV NVIDIA_VISIBLE_DEVICES=all
ENV OLLAMA_HOST=0.0.0.0:11434
WORKDIR /go/src/github.com/ollama/ollama
EXPOSE 11434

# Enforce non-root execution (OCI Container Hardening Checklist)
USER 53111:53111
ENTRYPOINT /bin/ollama
CMD serve
