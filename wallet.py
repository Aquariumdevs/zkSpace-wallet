#!/usr/bin/env python3
import subprocess
import json
import sys
import os
import hashlib
import requests
import math
import struct

def get_block_hash(height, tendermint_node_address="http://localhost:26657"):
    """
    Get the block hash for a given block height from a Tendermint node.

    :param height: The block height to query for.
    :param tendermint_node_address: The address of the Tendermint node (default is 'http://localhost:26657').
    :return: The block hash as a string if successful, None otherwise.
    """
    # Construct the URL for querying the block
    url = f"{tendermint_node_address}/block?height={height}"

    try:
        # Make the HTTP request to the Tendermint node
        response = requests.get(url)

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            block_data = response.json()

            # Extract the block hash
            block_hash = block_data['result']['block_id']['hash']

            return block_hash
        else:
            print(f"Failed to fetch block data: HTTP {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Error fetching block data: {e}")
        return None

# Path to the wallet state file
wallet_state_file = 'wallet_state.json'

# Function to convert integer to a hexadecimal string with proper zero padding
def int_to_hex_str(integer_value, byte_size=4):
    hex_str = format(integer_value, f'0{byte_size * 2}x')  # Multiplied by 2 for hex digit pair per byte
    return hex_str

# Function to load the wallet state from a file
def load_wallet_state():
    default_internal_state = {
        'prev_state_hash': '',
        'hidden_addresses': [],
        'hidden_input_txs': [],
        'hidden_output_txs': [],
        'balance': 0  # Internal balance separate from the public balance
    }
    default_state = {
        'address': '',
        'secret': '',
        'counter': 0,
        'balance': 0,  # Public balance
        'internal_state': default_internal_state,
        'state_hash': ''
    }
    if os.path.exists(wallet_state_file):
        with open(wallet_state_file, 'r') as file:
            state = json.load(file)
            state['internal_state'] = {**default_internal_state, **state.get('internal_state', {})}
            return {**default_state, **state}
    return default_state


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

def create_hidden_transaction(inputs, outputs):
    txid = generate_txid(inputs, outputs)  # Generate a unique ID for the transaction
    return {
        'txid': txid,
        'inputs': inputs,
        'outputs': outputs
    }

def generate_txid(inputs, outputs):
    data = json.dumps({'inputs': inputs, 'outputs': outputs}, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()

def derive_hidden_address(public_key, seed, index):
    data_to_hash = f"{public_key}{seed}{index}"
    hidden_address = hashlib.sha256(data_to_hash.encode()).hexdigest()
    return hidden_address

def initialize_hidden_state():
    state = load_wallet_state()
    public_key = state['public_key']
    private_key_seed = state['secret']  # This is used for deterministic derivation

    # Derive initial hidden addresses
    hidden_addresses = [derive_hidden_address(public_key, private_key_seed, i) for i in range(10)]  # For example, derive 10 addresses

    # Initialize other parts of the internal state
    state['internal_state']['hidden_addresses'] = hidden_addresses
    state['internal_state']['utxos'] = []  # Initialize with no UTXOs
    state['internal_state']['balance'] = 0  # Initialize hidden balance

    # Hash the internal state to get the initial state hash
    state['state_hash'] = calculate_state_hash(state['internal_state'])

    # Create a SNARK proof for the initial state validity (Placeholder for actual SNARK proof generation)
    state['internal_state']['initial_state_proof'] = create_initial_state_snark_proof(state['internal_state'])

    save_wallet_state(state)

def create_initial_state_snark_proof(internal_state):
    # Placeholder for actual SNARK proof logic
    # This should include generating a proof based on the internal state's data
    # Assume we return a proof identifier or object here
    return "initial_state_snark_proof"

def calculate_state_hash(internal_state):
    # Simple example - in practice, you might hash more detailed or structured data
    return hashlib.sha256(json.dumps(internal_state, sort_keys=True).encode()).hexdigest()


def add_hidden_address(state):
    # Assuming we have a number of hidden addresses already derived
    num_hidden_addresses = len(state['internal_state']['hidden_addresses'])
    public_key = state['public_key']
    private_key_seed = state['secret']  # Using the secret as the seed for derivation

    # Derive a new hidden address
    new_hidden_address = derive_hidden_address(public_key, private_key_seed, num_hidden_addresses)
    
    # Add the new hidden address to the internal state
    state['internal_state']['hidden_addresses'].append(new_hidden_address)

    # Save the updated state
    save_wallet_state(state)

    return new_hidden_address


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

def update_state_hash():
    state = load_wallet_state()
    if not all(key in state for key in ['secret', 'address', 'counter', 'state_hash']):
        print("Wallet is not properly initialized or missing vital information.")
        return

    secret = state['secret']
    state_hash = state['state_hash']  # Assume this is calculated elsewhere
    counter_hex = int_to_hex_str(int(state['counter']))
    source = int_to_hex_str(int(state['address']))

    show_balance()
    state = load_wallet_state()
    prev_balance = state['balance']

    try:
        update_output = call_go_wallet("UpdateTx", [secret, source, state_hash, counter_hex])
        show_balance()
        state = load_wallet_state()
        if prev_balance != state['balance']:
            print("Update successful!")
            state['counter'] += 1  # Increment the transaction counter
            save_wallet_state(state)
        else:
            print("Unsuccessful operation!")
    except Exception as e:
        print(f"Failed to update state hash: {e}")

def transfer_with_update_state_hash():
    state = load_wallet_state()
    if not all(key in state for key in ['secret', 'address', 'counter', 'state_hash']):
        print("Wallet is not properly initialized or missing vital information.")
        return

    state_backup = state

    secret = state['secret']
    state_hash = state['state_hash']  # Assume this is calculated elsewhere
    counter_hex = int_to_hex_str(int(state['counter']))
    source = int_to_hex_str(int(state['address']))

    target = input("Enter the target address index: ").strip()

    amount_input = input("Enter the amount to transfer: ").strip()
    if not amount_input.isdigit() or int(amount_input) <= 0:
        print("Invalid amount. Please enter a positive integer.")
        return

    # Convert the decimal amount to a hexadecimal string
    amount_hex = int_to_hex_str(int(amount_input))

    try:
        show_balance()
        state = load_wallet_state()
        prev_balance = state['balance']
        update_output = call_go_wallet("transferWithUpdateTx", [secret, source, target, amount_hex, state_hash, counter_hex])
        show_balance()
        state = load_wallet_state()
        if prev_balance != state['balance']:
            print("Update successful!")
            state['counter'] += 1  # Increment the transaction counter
            save_wallet_state(state)
        else:
            print("Unsuccessful operation!")
    except Exception as e:
        print(f"Failed to update state hash: {e}")
        save_wallet_state(state_backup)


def transfer_with_burn_to_stealth():
    state = load_wallet_state()
    if not all(key in state for key in ['secret', 'address', 'counter', 'state_hash']):
        print("Wallet is not properly initialized or missing vital information.")
        return

    state_backup = state

    secret = state['secret']
    source = int_to_hex_str(int(state['address']))

    # This is the burn address; funds sent here are considered 'burnt'
    burn_address = '00000000'  

    amount_input = input("Enter the amount to transfer to stealth: ").strip()
    if not amount_input.isdigit() or int(amount_input) <= 0:
        print("Invalid amount. Please enter a positive integer.")
        return

    amount = int(amount_input)
    if state['balance'] < amount:
        print("Insufficient balance to perform the operation.")
        return

    amount_hex = int_to_hex_str(amount)
    counter_hex = int_to_hex_str(int(state['counter']))
    state_hash = state['state_hash']  # The current state hash before updating

    show_balance()
    state = load_wallet_state()  # Reload state after the operation

    # Adding the burnt amount to the stealth UTXOs
    new_utxo = {'address': source, 'amount': amount}
    state['internal_state']['utxos'].append(new_utxo)
    state['internal_state']['balance'] += amount  # Update the stealth balance

    # Update the internal state hash after adding the new transaction
    new_state_hash = calculate_state_hash(state['internal_state'])
    state['state_hash'] = new_state_hash
    save_wallet_state(state)

    try:
        show_balance()
        state = load_wallet_state()
        prev_balance = state['balance']
        # Sending the transparent funds to be burnt in exchange for stealth funds
        transfer_output = call_go_wallet("transferWithUpdateTx", [secret, source, burn_address, amount_hex, state_hash, counter_hex])
       
        show_balance()
        state = load_wallet_state()  # Reload state after the operation

        if prev_balance == state['balance']:  # Checking if balance was correctly updated
            print("Failed to burn transparent funds. Transaction unsuccessful.")
            save_wallet_state(state_backup)
        else:
            print("Transparent funds successfully burnt. Updating stealth balance.")
            state['counter'] += 1  # Increment the transaction counter

            # Construct a new proof for the updated state
            new_proofs = construct_proofs(state, new_utxo)

            save_wallet_state(state)

            print(f"Stealth balance updated successfully. New state hash: {new_state_hash}")
            print(f"New proofs constructed for the updated state: {new_proofs}")
    except Exception as e:
        print(f"Failed to update state hash: {e}")
        save_wallet_state(state_backup)


def verify_proofs(proof, block_height, stealth_tx):
    hash = get_block_hash(block_height)
    # Simulate proof verification with public inputs and blockchain path
    print(f"Verifying proof {proof} for transaction {stealth_tx} against blockchain state hash {hash} ")
    return True  # Placeholder result

def construct_proofs(state, stealth_tx):
    # Combine the address and counter into a single 8-byte string for querying
    counter_hex = int_to_hex_str(int(state['counter']), 4)  # 4 bytes for the counter
    query_param = state['address'] + counter_hex
    print("1")
    try:
        byte_string = call_go_wallet("query", [query_param])
        print(byte_string)
        # blockchain_path = ''.join(format(int(b), '02x') for b in bytes_path)
        # Remove the square brackets and split the string into a list of string numbers
        byte_values = byte_string.strip('[]').split()
        # Convert each string number to an integer and then to a byte array
        blockchain_path = bytes([int(b) for b in byte_values])
        print(blockchain_path)
    except Exception as e:
        print(f"Failed to query blockchain path: {e}")
        return None
    print("2")
    # Convert the received binary data into a bytes object
    path_bytes = blockchain_path  # Assuming blockchain_path is already in binary format

    # Define the size of a hash (32 bytes for SHA-256)
    hash_size = 32
    offset = 0
    print("3")
    # Extracting the first leaf and path
    leafkey1 = path_bytes[offset:offset + 8]
    print(list(leafkey1))
    offset += 8
    leafval1 = path_bytes[offset:offset + hash_size]
    print(list(leafval1))
    offset += hash_size
    root = path_bytes[offset:offset + hash_size]
    print(root)
    offset += hash_size
    print("offset")
    print(offset)
    out1 = check_proof_print(leafkey1, leafval1, root, path_bytes[offset:])
    #path1, offset = unpack_siblings(path_bytes, offset, hash_size)
    print(offset)
    """
    print("4")
    # Extracting the second leaf and path
    leafkey2 = path_bytes[offset:offset + 8]
    print(leafkey2)
    offset += 8
    print(offset)
    leafval2 = path_bytes[offset:offset + hash_size]
    print(leafval2)
    offset += hash_size
    print(offset)
    #path2, offset = unpack_siblings(path_bytes, offset, hash_size)
    print("5")
    # Extracting the block height (assuming it's stored in the last 4 bytes)
    block_height = int.from_bytes(leafkey2, byteorder='big')
    root1 = leafval2
    #out1 = check_proof(hashlib.sha256, leafkey1, leafval1, root1, path1)
    root2 = get_block_hash(block_height)
    #out2 = check_proof(hashlib.sha256, leafkey2, leafval2, root2, path2)
    """
    # print(f"Leaves and paths unpacked. Block height: {block_height}")
    print(f"Constructing proofs for transaction {stealth_tx} with blockchain paths")
    print(out1)

    return "state_update_proof", "transaction_inclusion_proof"


HASH_LEN = hashlib.sha256().digest_size

def unpack_siblings(b):
    full_len = struct.unpack_from('<H', b, 0)[0]
    l = struct.unpack_from('<H', b, 2)[0]
    if len(b) < full_len:
        raise ValueError(f"expected len: {full_len}, current len: {len(b)}")

    bitmap_bytes = b[4:4 + l]
    bitmap = bytes_to_bitmap(bitmap_bytes)
    siblings_bytes = b[4 + l:full_len]
    i_sibl = 0
    empty_sibl = bytes(HASH_LEN)
    siblings = []
    for i in range(len(bitmap)):
        if i_sibl >= len(siblings_bytes):
            break
        if bitmap[i]:
            siblings.append(siblings_bytes[i_sibl:i_sibl + HASH_LEN])
            print("sibling:", list(siblings_bytes[i_sibl:i_sibl + HASH_LEN]))
            i_sibl += HASH_LEN
        else:
            siblings.append(empty_sibl)
            print("sibling:", list(empty_sibl))
    return siblings

def bytes_to_bitmap(bitmap_bytes):
    """Convert bitmap bytes to a list of boolean values."""
    print("3.7")
    bitmap = []
    if len(bitmap_bytes) == 0:
        bitmap_bytes = bytearray(8)

    for byte in bitmap_bytes:
        for i in range(8):
            # Shift bit and check if it's set
            bitmap.append(bool(byte & (1 << i) > 0))
    return bitmap


def get_path(num_levels, k):
    path = []
    for n in range(num_levels):
        byte_index = n // 8
        bit_index = n % 8
        byte_value = k[byte_index]
        bit_value = (byte_value & (1 << bit_index)) != 0
        path.append(bit_value)
    return path

def new_leaf_value(k, v):
    if len(k) > 255 or len(v) > 65535:
        raise ValueError(f"Key or value length is too long")
    hasher = hashlib.sha256()
    hasher.update(k + v + bytes([1]))
    leaf_key = hasher.digest()
    print("k:", list(k))
    print("v:", list(v))
    print("lk:", list(leaf_key))

    leaf_value = bytes([1, len(k)]) + k + v
    print("lv:", list(leaf_value))
    return leaf_key, leaf_value

def new_intermediate(l, r):
    if len(l) > 255:
        raise ValueError(f"Left key length is too long")
    b = bytes([2, len(l)]) + l + r
    hasher = hashlib.sha256()
    hasher.update(l + r)
    key = hasher.digest()
    print("IM:", list(key))
    return key, b

def check_proof_print(k, v, root, packed_siblings):
    siblings = unpack_siblings(packed_siblings)
    key_path = bytearray(math.ceil(len(siblings) / 8))
    key_path[:len(k)] = k

    key, _ = new_leaf_value(k, v)
    print("key:", list(key))

    path = get_path(len(siblings), key_path)
    for i in reversed(range(len(siblings))):
        if path[i]:
            key, _ = new_intermediate(siblings[i], key)
            print("L:", list(key))
        else:
            key, _ = new_intermediate(key, siblings[i])
            print("R:", list(key))

    if key == root:
        print("success")
        return True
    else:
        print("FAIL")
        return False


def receive_stealth():
    state = load_wallet_state()
    transaction_hex = input("Enter the transaction hex you received: ").strip()
    transaction_data = json.loads(bytes.fromhex(transaction_hex).decode())
    stealth_tx = transaction_data['utxo']
    proofs = transaction_data['proofs']

    blockchain_height = 1  # This would typically come from the proof analysis
    if verify_proofs(proofs, blockchain_height, stealth_tx):
        print("Proof verified successfully.")
   
        # Update the internal state with the received transaction
        state['internal_state']['utxos'].append(stealth_tx)
        state['internal_state']['balance'] += stealth_tx['amount']

        # Construct a new proof for the updated state
        new_state_hash = calculate_state_hash(state['internal_state'])
        state['state_hash'] = new_state_hash

        new_proofs = construct_proofs(state, stealth_tx)

        save_wallet_state(state)
        print(f"State updated successfully. New state hash: {new_state_hash}")
        print(f"New proofs constructed for the updated state: {new_proofs}")
    else:
        print("Proof verification failed.")

def send_stealth():
    state = load_wallet_state()
    to_address_hex = input("Enter the stealth address (hex) to send to: ").strip()
    amount = int(input("Enter the amount to send: ").strip())
    
    state_backup = state
 
    if state['internal_state']['balance'] < amount:
        print("Insufficient balance to perform the stealth transaction.")
        return

    stealth_tx = {'address': to_address_hex, 'amount': amount}
    previous_state_hash = state['state_hash']

    state['internal_state']['utxos'].append(stealth_tx)
    state['internal_state']['balance'] -= amount
    new_state_hash = calculate_state_hash(state['internal_state'])

    save_wallet_state(state)

    if not all(key in state for key in ['secret', 'address', 'counter', 'state_hash']):
        print("Wallet is not properly initialized or missing vital information.")
        return

    secret = state['secret']
    state_hash = state['state_hash']  # Assume this is calculated elsewhere
    counter_hex = int_to_hex_str(int(state['counter']))
    source = int_to_hex_str(int(state['address']))

    show_balance()
    state = load_wallet_state()
    prev_balance = state['balance']

    try:
        update_output = call_go_wallet("UpdateTx", [secret, source, state_hash, counter_hex])
        show_balance()
        state = load_wallet_state()
        if prev_balance != state['balance']:
            print("Update successful!")
            state['counter'] += 1  # Increment the transaction counter
            save_wallet_state(state)

            state = load_wallet_state()


            proofs = construct_proofs(state, stealth_tx)
            # Generate the transaction hex that will be sent to the receiver
            transaction_data = {'utxo': stealth_tx, 'proofs': proofs}
            transaction_hex = json.dumps(transaction_data).encode().hex()
    
            state['state_hash'] = new_state_hash
            save_wallet_state(state)
            print(f"Transaction hex to send: {transaction_hex}")

        else:
            print("Unsuccessful operation!")
            save_wallet_state(state_backup)
    except Exception as e:
        print(f"Failed to update state hash: {e}")
        save_wallet_state(state_backup)
            

def show_stealth_addresses():
    state = load_wallet_state()
    hidden_addresses = state['internal_state'].get('hidden_addresses', [])

    if hidden_addresses:
        print("Stealth Addresses:")
        for index, address in enumerate(hidden_addresses, 1):
            print(f"{index}. {address}")
    else:
        print("No stealth addresses found.")

def show_stealth_balance():
    state = load_wallet_state()
    stealth_balance = state['internal_state'].get('balance', 0)

    print(f"Stealth Balance: {stealth_balance}")


def help():
    print("Usage: wallet.py <command> \n")
    print("Available commands:")
    print("  init                  - Initializes the wallet by creating a new key pair.")
    print("  keys                  - Shows keys and information of the wallet.")
    print("  balance               - Shows the balance of the wallet.")
    print("  delete                - Deletes the local wallet state.")
    print("  create                - Used by a sponsor to create and fund a wallet on the blockchain.")
    print("  transfer              - Transfers funds from the wallet to another address.")
    print("  stake                 - Stakes a specified amount in the wallet.")
    print("  unstake               - Unstakes funds from the blockchain.")
    print("  update                - Updates hidden state hash on the blockchain.")
    print("  send_stealth          - Sends a stealth transaction to another stealth address.")
    print("  receive_stealth       - Receives a stealth transaction from another user.")
    print("  show_stealth_addresses - Shows all stealth addresses associated with the wallet.")
    print("  show_stealth_balance  - Shows the balance of the stealth wallet.")
    print("  transfer_to_stealth   - Transfers and burns transparent funds to stealth balance.")
    print("  help                  - Shows this help message.")
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
            print("7. Initialize Hidden State")
            print("8. Send Stealth Transaction")
            print("9. Receive Stealth Transaction")
            print("10. Show Stealth Addresses")
            print("11. Show Stealth Balance")
            print("12. Transfer to Stealth")
            print("x. Exit")

            choice = input("Select an operation: ").strip()
            if choice == '1':
                show_balance()
            elif choice == '2':
                transfer()
            elif choice == '3':
                stake()
            elif choice == '4':
                unstake()
            elif choice == '5':
                delete_wallet()
                break  # Exiting after deletion as no operations can be performed on a deleted wallet
            elif choice == '6':
                sponsor_create_account()
            elif choice == '7':
                initialize_hidden_state(state)
            elif choice == '8':
                send_stealth()
            elif choice == '9':
                receive_stealth()
            elif choice == '10':
                show_stealth_addresses()
            elif choice == '11':
                show_stealth_balance()
            elif choice == '12':
                transfer_with_burn_to_stealth()
            elif choice.lower() == 'x':
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
    elif function == 'update':
        update_state_hash()
    elif function == 'send_stealth':
        send_stealth()
    elif function == 'receive_stealth':
        receive_stealth()
    elif function == 'show_stealth_addresses':
        show_stealth_addresses()
    elif function == 'show_stealth_balance':
        show_stealth_balance()
    elif function == 'transfer_to_stealth':
        transfer_with_burn_to_stealth()
    elif function == 'help':
        help()
    else:
        # For other commands, pass them directly to the Go wallet
        output = call_go_wallet(function, args)
        print(output)

if __name__ == "__main__":
    main()
