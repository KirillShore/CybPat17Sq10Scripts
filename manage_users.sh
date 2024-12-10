#!/bin/bash

read -p "Please enter the path to set as HOME (e.g., /home/ratman): " CUSTOM_HOME

if [[ ! -d "$CUSTOM_HOME" ]]; then
    echo "Error: The provided path does not exist."
    exit 1
fi

USERS_FILE="$CUSTOM_HOME/Desktop/users.txt"
ADMINS_FILE="$CUSTOM_HOME/Desktop/admins.txt"

if [ ! -f "$USERS_FILE" ] || [ ! -f "$ADMINS_FILE" ]; then
    echo "Error: users.txt or admins.txt not found on Desktop."
    exit 1
fi

mapfile -t USERS_LIST < "$USERS_FILE"
mapfile -t ADMINS_LIST < "$ADMINS_FILE"

SYSTEM_USERS=$(awk -F: '($3 >= 1000) {print $1}' /etc/passwd)

function user_in_list() {
    local user="$1"
    shift
    local list=("$@")
    for item in "${list[@]}"; do
        if [[ "$item" == "$user" ]]; then
            return 0
        fi
    done
    return 1
}

EXCLUDE_USERS=("nobody" "noaccess" "nfsnobody")

for admin in "${ADMINS_LIST[@]}"; do
    if ! user_in_list "$admin" "${USERS_LIST[@]}"; then
        read -p "Admin '$admin' is not in users.txt. Do you want to add this admin to users.txt? (y/n) " confirm
        if [[ "$confirm" == "y" ]]; then
            echo "$admin" >> "$USERS_FILE"
            USERS_LIST+=("$admin")
            echo "Admin '$admin' has been added to users.txt."
        fi
    fi
done

for user in "${USERS_LIST[@]}"; do
    if ! id "$user" &>/dev/null; then
        read -p "User '$user' is in users.txt but does not exist on the system. Do you want to create this user? (y/n) " confirm
        if [[ "$confirm" == "y" ]]; then
            sudo adduser "$user"
            echo "User '$user' has been created."
        fi
    fi

    if ! getent group "$user" &>/dev/null; then
        sudo addgroup "$user"
        sudo usermod -g "$user" "$user"
        echo "Group '$user' has been created and user '$user' has been assigned to it."
    fi

    if user_in_list "$user" "${ADMINS_LIST[@]}"; then
        if ! groups "$user" | grep -q '\bsudo\b'; then
            read -p "User '$user' should be an admin. Do you want to add them to the sudo group? (y/n) " confirm
            if [[ "$confirm" == "y" ]]; then
                sudo usermod -aG sudo "$user"
                echo "User '$user' has been added to the sudo group."
            fi
        fi
    fi
done

for system_user in $SYSTEM_USERS; do
    if user_in_list "$system_user" "${EXCLUDE_USERS[@]}"; then
        continue
    fi

    if ! user_in_list "$system_user" "${USERS_LIST[@]}"; then
        read -p "User '$system_user' is not in users.txt. Do you want to delete this user? (y/n) " confirm
        if [[ "$confirm" == "y" ]]; then
            sudo deluser --remove-home "$system_user"
            sudo delgroup "$system_user"
            echo "User '$system_user' and their group have been deleted."
        fi
    fi

    if ! user_in_list "$system_user" "${ADMINS_LIST[@]}"; then
        if groups "$system_user" | grep -q '\bsudo\b'; then
            read -p "User '$system_user' is an admin but shouldn't be. Do you want to remove them from the sudo group? (y/n) " confirm
            if [[ "$confirm" == "y" ]]; then
                sudo deluser "$system_user" sudo
                echo "User '$system_user' has been removed from the sudo group."
            fi
        fi
    fi
done

for user in "${USERS_LIST[@]}"; do
    if ! id "$user" &>/dev/null; then
        echo "Warning: User '$user' could not be created automatically. Please create this user manually."
    else
        if user_in_list "$user" "${ADMINS_LIST[@]}" && ! groups "$user" | grep -q '\bsudo\b'; then
            echo "Warning: User '$user' should be an admin but was not added to the sudo group automatically. Please add manually."
        fi
        if ! getent group "$user" &>/dev/null; then
            echo "Warning: Group for user '$user' could not be created automatically. Please create this group manually."
        fi
    fi

done

for user in "${USERS_LIST[@]}"; do
    if [[ "$user" != "$CURRENT_USER" ]] && ! user_in_list "$user" "${ADMINS_LIST[@]}"; then
        echo "Changing password for user '$user'..."
        NEW_PASSWORD=$(openssl rand -base64 12)
        echo "$user:$NEW_PASSWORD" | sudo chpasswd
        echo "Password for user '$user' has been updated."
    fi
done

for user in "${USERS_LIST[@]}"; do
    if ! id "$user" &>/dev/null; then
        echo "Warning: User '$user' could not be created automatically. Please create this user manually."
    else
        if user_in_list "$user" "${ADMINS_LIST[@]}" && ! groups "$user" | grep -q '\bsudo\b'; then
            echo "Warning: User '$user' should be an admin but was not added to the sudo group automatically. Please add manually."
        fi
        if ! getent group "$user" &>/dev/null; then
            echo "Warning: Group for user '$user' could not be created automatically. Please create this group manually."
        fi
    fi
done

echo "script_run=1" > /tmp/script_status.sh

echo "custom_home=\"$CUSTOM_HOME\"" >> /tmp/script_status.sh

echo "Script execution completed."