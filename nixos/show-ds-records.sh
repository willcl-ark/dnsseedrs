#!/usr/bin/env bash

# Helper script to show DS records for dnsseedrs DNSSEC keys

set -euo pipefail

show_usage() {
	echo "Usage: $0 [INSTANCE_NAME]"
	echo ""
	echo "Show DS records for dnsseedrs DNSSEC keys."
	echo ""
	echo "Arguments:"
	echo "  INSTANCE_NAME  Name of the dnsseedrs instance (mainnet, signet, testnet, testnet4)"
	echo "                 If not provided, shows DS records for all enabled instances"
	echo ""
	echo "Examples:"
	echo "  $0 mainnet     # Show DS records for mainnet instance"
	echo "  $0             # Show DS records for all instances"
}

show_ds_records_for_instance() {
	local instance="$1"
	local keydir="/var/lib/dnsseedrs-${instance}/dnssec-keys"

	if [ ! -d "$keydir" ]; then
		echo "No DNSSEC keys directory found for instance: $instance"
		echo "Expected directory: $keydir"
		return 1
	fi

	echo "=== DS Records for dnsseedrs-${instance} ==="
	echo ""

	local found_keys=false
	for keyfile in "$keydir"/K*.key; do
		if [ -f "$keyfile" ]; then
			found_keys=true
			echo "Key file: $(basename "$keyfile")"
			dnssec-dsfromkey "$keyfile"
			echo ""
		fi
	done

	if [ "$found_keys" = false ]; then
		echo "No DNSSEC key files found in $keydir"
		echo "Make sure DNSSEC is enabled and keys have been generated."
		echo ""
		echo "To check if the key generation service ran:"
		echo "  systemctl status dnsseedrs-${instance}-dnssec-keys"
		echo ""
		echo "To manually generate keys:"
		echo "  systemctl start dnsseedrs-${instance}-dnssec-keys"
		return 1
	fi

	echo "Add these DS records to your DNS provider for the parent domain."
	echo ""
}

main() {
	local instance="${1:-}"

	if [ "$instance" = "-h" ] || [ "$instance" = "--help" ]; then
		show_usage
		exit 0
	fi

	# Check if dnssec-dsfromkey is available
	if ! command -v dnssec-dsfromkey >/dev/null 2>&1; then
		echo "Error: dnssec-dsfromkey command not found"
		echo "Make sure bind-utils or bind package is installed"
		exit 1
	fi

	if [ -n "$instance" ]; then
		# Show DS records for specific instance
		show_ds_records_for_instance "$instance"
	else
		# Show DS records for all instances
		local found_any=false
		for instance_dir in /var/lib/dnsseedrs-*; do
			if [ -d "$instance_dir" ]; then
				local instance_name
				instance_name=$(basename "$instance_dir" | sed 's/^dnsseedrs-//')
				if show_ds_records_for_instance "$instance_name" 2>/dev/null; then
					found_any=true
				fi
			fi
		done

		if [ "$found_any" = false ]; then
			echo "No dnsseedrs instances with DNSSEC keys found."
			echo ""
			echo "Make sure you have enabled DNSSEC for at least one instance:"
			echo ""
			echo "  services.dnsseedrs.mainnet = {"
			echo "    enable = true;"
			echo "    dnssec.enable = true;"
			echo "    # ... other options"
			echo "  };"
		fi
	fi
}

main "$@"
