#!/usr/bin/env python3
import subprocess
import json
import sys
import os

# Path to the wallet state file
wallet_state_file = 'wallet_state.json'

# Function to convert integer to a hexadecimal string with proper zero padding
def int_to_hex_str(integer_value, byte_size=4):
    hex_str = format(integer_value, f'0{byte_size * 2}x')  # Multiplied by 2 for hex digit pair per byte
    return hex_str

# Function to load the wallet state from a file
def load_wallet_state():
    if os.path.exists(wallet_state_file):
        with open(wallet_state_file, 'r') as file:
            return json.load(file)
    return {'address': '', 'secret': '', 'counter': 0, 'balance': 0}

# Function to save the wallet state to a file
def save_wallet_state(state):
    with open(wallet_state_file, 'w') as file:
        json.dump(state, file)

# Call the Go wallet command
def call_go_wallet(command, args):
    go_command = ["./wallet", command] + args
    output = []  # List to capture the output lines
    try:
        # Use Popen for real-time output
        with subprocess.Popen(go_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
            for line in process.stdout:
                #print(line, end='')  # Print output line by line in real-time
                output.append(line.strip())  # Add line to output list
            process.wait()  # Wait for the subprocess to finish
            if process.returncode != 0:
                raise Exception(f"Error executing command '{command}' with return code {process.returncode}")
    except Exception as e:
        print(f"Failed to execute command '{command}': {e}")
        sys.exit(1)
    
    return '\n'.join(output)  # Return the captured output as a single string


# Initialize the wallet by creating a key pair and saving the initial state
def initialize_wallet():
    state = load_wallet_state()
    if not state.get('address'):
        print("Creating new key pair...")
        while True:
            source = input("Enter the 4-byte index of the sponsor account: ").strip()
            counter = input("Enter the transaction counter for the sponsor account: ").strip()

            # Validate the input format, assuming 4-byte index and counter should be hexadecimal
            if len(source) != 8 or not all(c in '0123456789abcdefABCDEF' for c in source):
                print("Invalid source index format. It must be an 8-character hexadecimal.")
                continue
            if len(counter) != 8 or not all(c in '0123456789abcdefABCDEF' for c in counter):
                print("Invalid counter format. It must be an 8-character hexadecimal.")
                continue

            try:
                output = call_go_wallet("createKeys", [source, counter])
                keys = output.split()
                # Ensure we correctly map the output to state variables
                state['secret'] = keys[0]
                state['public_key'] = keys[2]
                state['bls_public_key'] = keys[3]
                state['pop'] = keys[4]  # Assuming the fourth element is the Proof of Possession (POP)

                save_wallet_state(state)
                print(f"Wallet initialized with secret key: {state['secret']}")
                print(f"Public Key: {state['public_key']}")
                print(f"BLS Public Key: {state['bls_public_key']}")
                print(f"Proof of Possession: {state['pop']}")
                print(f"Credentials (copy and send the following 3 values to your wallet creator): {state['public_key']} {state['bls_public_key']} {state['pop']}")
                break  # Exit the loop on success
            except Exception as e:
                print(f"Failed to create key pair: {e}")
                print("Please check the input and try again.")

# Function to display the wallet keys
def show_keys():
    state = load_wallet_state()

    print("Wallet Information:")
    print(f"Secret Key: {state.get('secret', 'Not Available')}")
    print(f"Public Key: {state.get('public_key', 'Not Available')}")
    print(f"BLS Public Key: {state.get('bls_public_key', 'Not Available')}")


# Function to display the wallet balance
def show_balance():
    state = load_wallet_state()

    address = state.get('address')
    if not address:
        print("Local Address Index: Not Available - Attempting to retrieve from blockchain...")
        if 'bls_public_key' in state:
            try:
                output = call_go_wallet("query", [state['bls_public_key']])
                address_bytes = output.strip('[]').split()
                if len(address_bytes) == 4:
                    # Convert from list of byte values to hex string
                    address = ''.join(format(int(b), '02x') for b in address_bytes)
                    # Update state with new address
                    state['address'] = address
                    save_wallet_state(state)
                    print(f"Retrieved 4-byte Address Index: {address}")
                else:
                    print("The wallet is not yet on-chain or there's a connection issue.")
                    return
            except Exception as e:
                print(f"Failed to query on-chain information: {e}")
                return
        else:
            print("BLS Public Key not found. Please initialize the wallet.")
            return

    # Query for balance using the 4-byte address
    try:
        balance_output = call_go_wallet("query", [address])
        balance_bytes = balance_output.strip('[]').split()
        if len(balance_bytes) > 4:
            # Decode the big-endian 4-byte address to a single numerical value
            balance = int(''.join(format(int(b), '02x') for b in balance_bytes[:4]), 16)
            state['balance'] = balance
            save_wallet_state(state)
            print(f"Balance: {balance}")
        else:
            print("Failed to retrieve a valid balance. The response format is incorrect.")
    except Exception as e:
        print(f"Failed to query balance information: {e}")


def delete_wallet():
    global wallet_state_file  # Ensure the function knows about the global variable
    if os.path.exists(wallet_state_file):
        try:
            os.remove(wallet_state_file)
            print("Wallet file has been successfully deleted.")
        except Exception as e:
            print(f"Failed to delete wallet file: {e}")
    else:
        print("Wallet file does not exist.")

def sponsor_create_account():
    # Load the sponsor's wallet state and verify its initialization
    state = load_wallet_state()
    required_keys = ['secret', 'address', 'counter']
    if not all(key in state and state[key] for key in required_keys):
        print("Sponsor's wallet is not properly initialized or missing vital information.")
        return

    print("Enter the Credentials: output from the wallet initialization of the wallet to be sponsored:")
    init_output = input().strip().split()
    if len(init_output) < 3:
        print("Invalid input. The initialization output should contain at least 3 elements.")
        return

    # Extracting new wallet's public key, BLS public key, and POP from the input
    spubkey, blspk, pop = init_output[0], init_output[1], init_output[2]
    print("!!!",len(spubkey), len(blspk), len(pop))
    amount_input = input("Enter the amount to fund the new wallet: ").strip()
    if not amount_input.isdigit() or int(amount_input) <= 0:
        print("Invalid amount. Please enter a positive integer.")
        return

    # Convert the decimal amount to a hexadecimal string
    amount_hex = int_to_hex_str(int(amount_input))

    # Sponsor's secret and other details
    secret_sponsor = state['secret']
    source = state['address']
    counter = int_to_hex_str(int(state['counter']))  # Assuming counter is large, adjust byte size as needed

    show_balance()
    state = load_wallet_state()
    prev_balance = state['balance']

    try:
        account_creation_output = call_go_wallet(
            "createAccountTx",
            [secret_sponsor, spubkey, blspk, pop, source, amount_hex, counter]
        )
        show_balance()
        state = load_wallet_state()
        if prev_balance != state['balance']:
            print("Account creation successful!")
            state['counter'] += 1  # Increment the transaction counter
            save_wallet_state(state)
        else:
            print("Unsuccessful operation!")

        #print(account_creation_output)

        save_wallet_state(state)  # Save the updated state
    except Exception as e:
        print(f"Failed to create account: {e}")


def transfer():
    state = load_wallet_state()

    # Check if the wallet has been properly initialized
    if not all(key in state for key in ['secret', 'address', 'counter']):
        print("Wallet is not properly initialized.")
        return

    secret = state['secret']
    source = state['address']
    counter = state['counter']

    target = input("Enter the target address index: ").strip()

    amount_input = input("Enter the amount to transfer: ").strip()
    if not amount_input.isdigit() or int(amount_input) <= 0:
        print("Invalid amount. Please enter a positive integer.")
        return

    # Convert the decimal amount to a hexadecimal string
    amount_hex = int_to_hex_str(int(amount_input))

    # Convert the decimal counter to a hexadecimal string
    counter_hex = int_to_hex_str(int(counter))

    show_balance()
    state = load_wallet_state()
    prev_balance = state['balance']


    try:
        transfer_output = call_go_wallet("transferTx", [secret, source, target, amount_hex, counter_hex])
        show_balance()
        state = load_wallet_state()
        if prev_balance != state['balance']:
            print("Transfer successful!")
            state['counter'] += 1  # Increment the transaction counter
            save_wallet_state(state)
        else:
            print("Unsuccessful operation!")
        #print(transfer_output)
    except Exception as e:
        print(f"Failed to transfer: {e}")

def stake():
    state = load_wallet_state()

    # Check if the wallet has been properly initialized
    if not all(key in state for key in ['secret', 'address', 'counter']):
        print("Wallet is not properly initialized.")
        return

    secret = state['secret']
    source = state['address']
    counter = state['counter']

    amount_input = input("Enter the amount to stake: ").strip()
    if not amount_input.isdigit() or int(amount_input) <= 0:
        print("Invalid amount. Please enter a positive integer.")
        return

    # Convert the decimal amount to a hexadecimal string
    amount_hex = int_to_hex_str(int(amount_input))

    # Convert the decimal counter to a hexadecimal string
    counter_hex = int_to_hex_str(int(counter))

    show_balance()
    state = load_wallet_state()
    prev_balance = state['balance']

    try:
        stake_output = call_go_wallet("stakeTx", [secret, source, amount_hex, counter_hex])
        show_balance()
        state = load_wallet_state()
        if prev_balance != state['balance']:
            print("Staking successful!")
            state['counter'] += 1  # Increment the transaction counter
            save_wallet_state(state)
        else:
            print("Unsuccessful operation!")

        #print(stake_output)
    except Exception as e:
        print(f"Failed to stake: {e}")

def unstake():
    state = load_wallet_state()

    # Check if the wallet has been properly initialized
    if not all(key in state for key in ['secret', 'address', 'counter']):
        print("Wallet is not properly initialized.")
        return

    secret = state['secret']
    source = state['address']
    counter = state['counter']

    # Convert the decimal counter to a hexadecimal string
    counter_hex = int_to_hex_str(int(counter))

    try:
        # Increment the local counter for this new transaction
        state['counter'] += 1
        save_wallet_state(state)

        stake_output = call_go_wallet("releaseTx", [secret, source, counter_hex])
        print("Unstaking successful:")
        print(stake_output)
    except Exception as e:
        print(f"Failed to unstake: {e}")

def help():
    print("Usage: wallet.py <command> \n")
    print("Available commands:")
    print("  init     - Initializes the wallet by creating a new key pair.")
    print("  keys     - Shows keys and information of the wallet.")
    print("  balance  - Shows the balance of the wallet.")
    print("  delete   - Deletes the local wallet state.")
    print("  create   - Used by a sponsor to create and fund a wallet on the blockchain.")
    print("  transfer - Transfers funds from the wallet to another address.")
    print("  stake    - Stakes a specified amount in the wallet.")
    print("  unstake  - Unstakes funds from the blockchain.")
    print("  help     - Shows this help message.")
    print("\nFor other commands, they will be passed directly to the low level Go wallet with the provided arguments.")

def interactive():
    state = load_wallet_state()
    if not state or 'secret' not in state or 'address' not in state:
        print("No wallet found. Initializing new wallet...")
        initialize_wallet()
        state = load_wallet_state()  # Reload after initialization

    show_keys()
    show_balance()

    # Check again after initialization attempt
    if 'secret' in state and 'address' in state:
        while True:
            print("\nWallet Operations:")
            print("1. Show Balance")
            print("2. Transfer Funds")
            print("3. Stake Funds")
            print("4. Unstake Funds")
            print("5. Delete Wallet")
            print("6. Fund New Wallet")
            print("7. Exit")

            choice = input("Select an operation (1-7): ").strip()
            if choice == '1':
                show_balance()
            elif choice == '2':
                transfer()
            elif choice == '3':
                stake()
            elif choice == '4':
                unstake()  # Assuming you have an 'unstake' function implemented
            elif choice == '5':
                delete_wallet()
                break  # Exiting after deletion as no operations can be performed on a deleted wallet
            elif choice == '6':
                sponsor_create_account()
            elif choice == '7':
                print("Exiting wallet application.")
                break
            else:
                print("Invalid choice, please select a valid operation.")
    else:
        print("Wallet initialization failed or was incomplete. Please check and try again.")


def main():
    if len(sys.argv) < 2:
        interactive()
        sys.exit(1)

    function = sys.argv[1]
    args = sys.argv[2:]

    if function == 'init':
        initialize_wallet()
    elif function == 'keys':
        show_keys()
    elif function == 'balance':
        show_balance()
    elif function == 'delete':
        delete_wallet()
    elif function == 'create':
        sponsor_create_account()
    elif function == 'transfer':
        transfer()
    elif function == 'stake':
        stake()
    elif function == 'unstake':
        unstake()
    elif function == 'help':
        help()
    else:
        # For other commands, pass them directly to the Go wallet
        output = call_go_wallet(function, args)
        print(output)

if __name__ == "__main__":
    main()
