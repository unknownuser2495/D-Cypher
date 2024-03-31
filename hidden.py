import cv2

def encode_bit(image, bit, pixel_index, channel_index):
    height, width, channels = image.shape
    pixel = image[pixel_index // width, pixel_index % width]

    # Set or clear the least significant bit based on the value of 'bit'
    if bit == 1:
        pixel[channel_index] |= 1  # Set bit to 1 using bitwise OR
    else:
        pixel[channel_index] &= ~1  # Set bit to 0 using bitwise AND with complement of 1
        
    image[pixel_index // width, pixel_index % width] = pixel
    return image

def decode_bit(image, pixel_index, channel_index):
    height, width, channels = image.shape
    pixel = image[pixel_index // width, pixel_index % width]
    
    # Extract the least significant bit of the specified channel
    bit = pixel[channel_index] & 1
    return bit

def encode_data(image_path, data):
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        raise TypeError("Unsupported data type. Only string or bytes are supported.")

    image = cv2.imread(image_path)
    height, width, channels = image.shape
    pixel_count = width * height
    binary_data = ''.join(format(byte, '08b') for byte in data_bytes)
    data_length = len(data_bytes)
    if data_length * 8 > pixel_count * channels:
        raise Exception("Input data is too large to encode")

    pixel_index = 0
    channel_index = 0

    for bit in binary_data:
        image = encode_bit(image, int(bit), pixel_index, channel_index)
        if channel_index<2:
            channel_index += 1
        else:
            pixel_index += 1
            channel_index = 0
        
    print("Encoding successful.")
    return image

def decode_data(image_path, data_length):
    image = cv2.imread(image_path)
    height, width, channels = image.shape
    pixel_count = width * height
    binary_data = ''
    pixel_index = 0
    channel_index = 0

    for _ in range(data_length * 8):
        binary_data += str(decode_bit(image, pixel_index, channel_index))
        if channel_index<2:
            channel_index += 1
        else:
            pixel_index += 1
            channel_index = 0

    decoded_data = bytes(int(binary_data[i:i + 8], 2) for i in range(0, len(binary_data), 8))
    print("Decoding successful.")
    return decoded_data