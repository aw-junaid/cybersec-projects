#!/bin/bash
set -euo pipefail

# Signing script with support for both keyless and keyed signing

IMAGE_NAME="${1}"
SIGNING_MODE="${2:-keyless}"  # keyless or keyed
COSIGN_KEY_PATH="${3:-}"
COSIGN_PASSWORD="${4:-}"

log() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

validate_dependencies() {
    if ! command -v cosign &> /dev/null; then
        error "cosign not found in PATH"
        return 1
    fi
}

keyless_sign() {
    local image="$1"
    log "Performing keyless signing for $image"
    
    # Keyless signing using OIDC
    if cosign sign --yes "$image"; then
        log "Keyless signing completed successfully"
        return 0
    else
        error "Keyless signing failed"
        return 1
    fi
}

keyed_sign() {
    local image="$1"
    local key_path="$2"
    local password="$3"
    
    if [[ -z "$key_path" || ! -f "$key_path" ]]; then
        error "Cosign key not found at $key_path"
        return 1
    fi
    
    log "Performing keyed signing for $image"
    
    # Export password for cosign
    export COSIGN_PASSWORD="$password"
    
    if cosign sign --yes --key "$key_path" "$image"; then
        log "Keyed signing completed successfully"
        return 0
    else
        error "Keyed signing failed"
        return 1
    fi
}

generate_signing_key() {
    local key_prefix="${1:-cosign}"
    local output_dir="${2:-./keys}"
    
    mkdir -p "$output_dir"
    local private_key="$output_dir/${key_prefix}.key"
    local public_key="$output_dir/${key_prefix}.pub"
    
    log "Generating new cosign key pair..."
    
    if cosign generate-key-pair --output-key-prefix "$output_dir/$key_prefix"; then
        log "Key pair generated:"
        log "Private key: $private_key"
        log "Public key: $public_key"
        log "Store these keys securely!"
        return 0
    else
        error "Failed to generate key pair"
        return 1
    fi
}

main() {
    validate_dependencies
    
    case "$SIGNING_MODE" in
        "keyless")
            keyless_sign "$IMAGE_NAME"
            ;;
        "keyed")
            if [[ -z "$COSIGN_KEY_PATH" ]]; then
                error "Key path required for keyed signing"
                return 1
            fi
            keyed_sign "$IMAGE_NAME" "$COSIGN_KEY_PATH" "$COSIGN_PASSWORD"
            ;;
        "generate-keys")
            generate_signing_key "ci-signing" "./keys"
            ;;
        *)
            error "Invalid signing mode: $SIGNING_MODE"
            echo "Usage: $0 <image-name> [keyless|keyed|generate-keys] [key-path] [password]"
            return 1
            ;;
    esac
}

# If script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
