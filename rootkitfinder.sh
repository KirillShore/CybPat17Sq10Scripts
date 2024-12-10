#!/bin/bash

output_file="rootkit_check_results.log"

check_suspicious_libraries() {
  echo "[+] Checking for suspicious shared libraries..." | tee -a "$output_file"
  suspicious_libs=("evil_rabbit.so" "libmalicious.so" "libhax.so")

  for lib in "${suspicious_libs[@]}"; do
    lsof | grep "$lib" >> "$output_file" 2>/dev/null
  done

  echo "[+] Suspicious library check complete." | tee -a "$output_file"
}

check_suspicious_processes() {
  echo "[+] Checking for processes loading suspicious shared libraries..." | tee -a "$output_file"

  if [ -f "$output_file" ]; then
    grep -E '/usr/src/evil_rabbit.so' "$output_file" | awk '{print $2}' | sort | uniq | while read -r pid; do
      echo "[+] Details for PID $pid:" | tee -a "$output_file"
      ps -p "$pid" -o pid,cmd >> "$output_file"
      cat "/proc/$pid/maps" >> "$output_file"
    done
  fi

  echo "[+] Process check complete." | tee -a "$output_file"
}

scan_open_files() {
  echo "[+] Scanning open files for suspicious activity..." | tee -a "$output_file"
  lsof +L1 | grep deleted >> "$output_file" 2>/dev/null
  echo "[+] Open file scan complete." | tee -a "$output_file"
}

rm -f "$output_file"
echo "[+] Starting rootkit check..." | tee "$output_file"
check_suspicious_libraries
check_suspicious_processes
scan_open_files
echo "[+] Rootkit check complete. Results saved to $output_file"
