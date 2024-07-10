import os
import subprocess
import socket

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error: {e}")
        return None
def install_wireguard():
    print("Installing WireGuard...")
    os.system("sudo apt update")
    os.system("sudo apt install -y wireguard")

def generate_wireguard_keys():
    print("Generating WireGuard keys...")
    private_key = subprocess.check_output("wg genkey", shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f"echo {private_key} | wg pubkey", shell=True).decode('utf-8').strip()
    return private_key, public_key


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
    subprocess.run("curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.1/install.sh | bash", shell=True, check=True)
    
    os.environ["NVM_DIR"] = os.path.expanduser("~/.nvm")
    source_nvm = """
    export NVM_DIR="${HOME}/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    """

    install_node = """
    nvm install v20.15.1
    """

    full_command = f"{source_nvm}\n{install_node}"
    subprocess.run(full_command, shell=True, executable="/bin/bash", check=True)

    subprocess.run(f"source {os.environ['NVM_DIR']}/nvm.sh && nvm use v20.15.1 && nvm alias default v20.15.1", shell=True, executable="/bin/bash", check=True)

    try:
        result = subprocess.run("node --version", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(f"Node.js version installed: {result.stdout.decode().strip()}")
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        print("Node.js is not correctly installed.")

    try:
        subprocess.run("echo 'export PATH=\"$NVM_DIR/versions/node/v20.15.1/bin:$PATH\"' >> ~/.bashrc", shell=True, check=True)
        subprocess.run("source ~/.bashrc", shell=True, check=True)
        print("Node.js added to PATH successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error adding Node.js to PATH: {e}")

def clone_github_repo():
    github_username = '0x7amza'
    github_password = input("Enter your GitHub token: ")
    repo_url = "github.com/0x7amza/WireGuardManager.git"  

    clone_command = f"git clone https://{github_username}:{github_password}@{repo_url} "
    os.system(clone_command)

    current_directory = os.getcwd()    
    cloned_directory = os.path.join(current_directory, "WireGuardManager")

    if os.path.exists(cloned_directory):
        parent_directory = os.path.abspath(os.path.join(current_directory, os.pardir))
        move_command = f"mv {cloned_directory} {parent_directory}"
        os.system(move_command)
    else:
        print("Error: Cloning repository failed.")


if __name__ == "__main__":
    install_wireguard()
    private_key, public_key = generate_wireguard_keys()
    configure_wireguard(private_key, public_key)
    enable_ip_forwarding()
    install_nvm_node()
    clone_github_repo()
