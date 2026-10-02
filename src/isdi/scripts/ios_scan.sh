#!/bin/bash
idb=pymobiledevice3
if [ -n "${PREFIX:-}" ]; then
    idb="python3 -m isdi.scanner.pmd3_wrapper"
    if command -v termux-usb >/dev/null 2>&1; then
        termux-usb -r -E -e "usbmuxd -f -v" "$(termux-usb -l | python -c "import sys, json; a=json.load(sys.stdin); print(a[0] if len(a)>0 else '');")"
    fi
elif [ -f /proc/version ] && grep -qi microsoft /proc/version; then
    # platform="wsl"
    idb=pymobiledevice3.exe
fi

# test if idb is installed
if ! command -v "${idb%% *}" > /dev/null 2>&1

then
    echo "idb could not be found. Please install it first."
    exit 1
fi
if [ $# -ne 2 ]; then
    echo "Usage: $0 <serial> <dumpfile>"
    exit 1
fi
serial=(--udid "$1")
outf="$2"

printf "Serial: %s\n" "${serial[@]}"

# Always read the phone: a cached dump would hide apps installed or removed
# since the last scan. The caller reuses a dump within a single scan.
# shellcheck disable=SC2086  # $idb may be a multi-word command
if ! apps=$(${idb} apps list "${serial[@]}"); then
    echo "Error: could not list apps (is the phone unlocked and trusted?)" >&2
    exit 1
fi
# shellcheck disable=SC2086
if ! devinfo=$(${idb} lockdown info "${serial[@]}"); then
    echo "Error: could not read device info" >&2
    exit 1
fi

# Write atomically so a failed run never leaves a half-written dump behind.
tmpf="$outf.tmp.$$"
if printf '{\n    "apps": %s,\n    "devinfo": %s\n}\n' "$apps" "$devinfo" > "$tmpf" \
    && mv -f "$tmpf" "$outf"; then
    echo "Dump completed successfully: $outf"
    exit 0
fi
rm -f "$tmpf"
echo "Error: Failed to create dump file" >&2
exit 1
