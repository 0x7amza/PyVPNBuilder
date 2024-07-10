import os
import subprocess
import socket

def install_wireguard():
    print("Installing WireGuard...")
    os.system("sudo apt update")
    os.system("sudo apt install -y wireguard")

def generate_wireguard_keys():
    print("Generating WireGuard keys...")
    private_key = subprocess.check_output("wg genkey", shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f"echo {private_key} | wg pubkey", shell=True).decode('utf-8').strip()
    return private_key, public_key

def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def configure_wireguard(private_key, public_key):
    print("Configuring WireGuard...")
    ip_address = "10.0.0.1"  
    peer_port = "51820"  
    peer_ip = get_local_ip()  
    peer_endpoint = f"{peer_ip}:{peer_port}"
    peer_allowed_ips = "0.0.0.0/0"  
    config_content = f"""
[Interface]
PrivateKey = {private_key}
Address = {ip_address}/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -o eth0 -j ACCEPT; iptables -A FORWARD -i eth0 -o %i -j ACCEPT; iptables -A FORWARD -i %i -o %i -j DROP; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o eth0 -j ACCEPT; iptables -D FORWARD -i eth0 -o %i -j ACCEPT; iptables -D FORWARD -i %i -o %i -j DROP; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = {public_key}
Endpoint = {peer_endpoint}
AllowedIPs = {peer_allowed_ips}
    """
    with open("/etc/wireguard/wg0.conf", "w") as f:
        f.write(config_content)
    os.system("sudo systemctl enable wg-quick@wg0")
    os.system("sudo systemctl start wg-quick@wg0")

def enable_ip_forwarding():
    print("Enabling IP forwarding...")
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")
    with open("/etc/sysctl.conf", "a") as f:
        f.write("net.ipv4.ip_forward=1\n")

def install_nvm_node():
    print("Installing NVM...")
    os.system("curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash")
    os.system('source ~/.bashrc')
    os.system("nvm install v20.15.1")
    os.system("nvm use v20.15.1")
    os.system("nvm alias default v20.15.1")

def clone_github_repo():
    github_username = input("Enter your GitHub username: ")
    github_password = input("Enter your GitHub password: ")
    repo_url = input("Enter the GitHub repository URL: ")
    
    current_directory = os.getcwd()
    parent_directory = os.path.abspath(os.path.join(current_directory, os.pardir))
    
    clone_command = f"git clone https://{github_username}:{github_password}@{repo_url} {parent_directory}"
    os.system(clone_command)

if __name__ == "__main__":
    install_wireguard()
    private_key, public_key = generate_wireguard_keys()
    configure_wireguard(private_key, public_key)
    enable_ip_forwarding()
    install_nvm_node()
    clone_github_repo()
