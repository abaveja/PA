import csv
import random
import time
import paramiko
from time import sleep

# Function to read CSV file and return list of dictionaries
def read_csv(file_path):
    data = []
    with open(file_path, 'r') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            data.append(row)
    return data

# Function to initiate SSH connection
def initiate_ssh(ip, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=username, password=password)
        print(f"SSH connection to {ip} successful!")
        time.sleep(3)  # Wait for 3 seconds
    except paramiko.AuthenticationException:
        print(f"Failed to connect to {ip} - Authentication failed.")
    except paramiko.SSHException as e:
        print(f"Failed to connect to {ip} - SSH error: {e}")
    except Exception as e:
        print(f"Failed to connect to {ip} - Error: {e}")
    finally:
        ssh.close()

# Load CSV data
csv_file_path = r'/home/cortex/data/users_ssh.csv'
data = read_csv(csv_file_path)

# Randomly select a row from CSV data
selected_row = random.choice(data)

# Extract necessary information
# full_name = selected_row['ï»¿full_name']
# username = selected_row['user_name']
# hostname = selected_row['host_name']
# ip = selected_row['Ip']
remote_ip = '192.168.1.201'  # Replace with your remote IP address
password = 'password'  # Password for SSH login

# Initiate SSH connection
while True:
    selected_row = random.choice(data)
    username = selected_row['user_name']
    print(remote_ip, username, password)
    initiate_ssh(remote_ip, username, password)
    wait = random.choice(range(0, 600))
    print(f"waiting {wait}")
    sleep(wait)

