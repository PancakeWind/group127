import hashlib

def length_extension_attack(original_hash, original_message, additional_data, original_length):
    # Assuming original_hash is the SHA-256 hash of original_message
    # original_length is the length of the original_message in bits

    # Calculate the padding required for the original_message
    padding = calculate_sha256_padding(original_length)

    # The state of the SHA-256 hash after processing the original_message
    # (the last 8 words of the SHA-256 intermediate hash)
    state = original_hash

    # Initialize a new SHA-256 hash object
    sha256 = hashlib.sha256()

    # Update the hash object with the additional_data
    sha256.update(additional_data.encode())

    # Calculate the length of the combined message (original_message + padding + additional_data)
    combined_length = original_length + len(padding) + len(additional_data) * 8

    # Update the internal state of the SHA-256 hash object with the length and padding
    sha256._sha.update(b'\x80' + b'\x00' * ((56 - (combined_length + 1) % 64) % 64))
    sha256._sha.update(combined_length.to_bytes(8, 'big'))

    # Finalize the hash to get the length-extended hash
    length_extended_hash = sha256.hexdigest()

    return length_extended_hash

def calculate_sha256_padding(message_length):
    # Calculate the SHA-256 padding for a given message length in bits
    padding_length = (448 - (message_length + 1) % 512) % 512
    padding = b'\x80' + b'\x00' * (padding_length // 8) + message_length.to_bytes(8, 'big')
    return padding

# Example usage
original_message = "Original message"
additional_data = "Additional data"
original_hash = hashlib.sha256(original_message.encode()).hexdigest()
original_length = len(original_message) * 8  # Length in bits

length_extended_hash = length_extension_attack(original_hash, original_message, additional_data, original_length)

print("Original hash:", original_hash)
print("Length-extended hash:", length_extended_hash)
