#!/bin/bash

STATUS_FILE="/tmp/script_status.sh"
if [[ ! -f "$STATUS_FILE" ]]; then
    echo "Error: The initial program has not been executed. Please run it first."
    exit 1
fi

source "$STATUS_FILE"

if [[ -z "$custom_home" || ! -d "$custom_home" ]]; then
    echo "Error: The CUSTOM_HOME path is invalid or not set."
    exit 1
fi

USERS_FILE="$custom_home/Desktop/users.txt"
ADMINS_FILE="$custom_home/Desktop/admins.txt"

if [[ ! -f "$USERS_FILE" || ! -f "$ADMINS_FILE" ]]; then
    echo "Error: users.txt or admins.txt not found in the specified CUSTOM_HOME path."
    exit 1
fi

mapfile -t USERS_LIST < "$USERS_FILE"
mapfile -t ADMINS_LIST < "$ADMINS_FILE"

GRUB_USERS_DIR="/etc/grub.d"
if [[ -d "$GRUB_USERS_DIR" ]]; then
    for grub_file in "$GRUB_USERS_DIR"/*; do
        if [[ -f "$grub_file" && -w "$grub_file" ]]; then
            echo "Checking unauthorized entries in $grub_file..."
            for user in $(awk -F: '($3 >= 1000) {print $1}' /etc/passwd); do
                if ! [[ "${USERS_LIST[*]}" =~ $user ]]; then
                    sed -i "/$user/d" "$grub_file"
                    echo "Removed unauthorized user '$user' from $grub_file."
                fi
            done
        fi
    done
fi

APT_SOURCES_DIR="/etc/apt/sources.list.d"
if [[ -d "$APT_SOURCES_DIR" ]]; then
    echo "Checking and removing unauthorized PPAs from $APT_SOURCES_DIR..."
    for ppa_file in "$APT_SOURCES_DIR"/*.list; do
        if [[ -f "$ppa_file" && -w "$ppa_file" ]]; then
            echo "Inspecting $ppa_file..."
            for line in $(cat "$ppa_file"); do
                AUTHORIZED_PPA=false
                if [[ "$line" == *"ubuntu.com"* ]]; then
                    AUTHORIZED_PPA=true
                fi
                if [[ "$AUTHORIZED_PPA" == false ]]; then
                    echo "Unauthorized PPA found: $line"
                    sed -i "/$line/d" "$ppa_file"
                    echo "Removed unauthorized PPA entry: $line"
                fi
            done
        fi
    done
fi

echo "User and PPA scan completed. Unauthorized entries have been removed."