import cv2
import numpy as np

def encode_bit(image, bit, pixel_index, channel_index):
    height, width, channels = image.shape
    pixel = image[pixel_index // width, pixel_index % width]
    mask_one = [1, 2, 4, 8, 16, 32, 64, 128]
    mask_zero = [254, 253, 251, 247, 239, 223, 191, 127]

    if bit == 1:
        pixel[channel_index] |= mask_one[channel_index]
    else:
        pixel[channel_index] &= mask_zero[channel_index]

    image[pixel_index // width, pixel_index % width] = pixel
    return image

def decode_bit(image, pixel_index, channel_index):
    height, width, channels = image.shape
    pixel = image[pixel_index // width, pixel_index % width]
    mask_one = [1, 2, 4, 8, 16, 32, 64, 128]

    bit = pixel[channel_index] & mask_one[channel_index] != 0
    return int(bit)

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
        pixel_index += 1
        if pixel_index >= pixel_count:
            pixel_index = 0
            channel_index = (channel_index + 1) % channels
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
        pixel_index += 1
        if pixel_index >= pixel_count:
            pixel_index = 0
            channel_index = (channel_index + 1) % channels

    decoded_data = bytes(int(binary_data[i:i + 8], 2) for i in range(0, len(binary_data), 8))
    print("Decoding successful.")
    return decoded_data

#################################################################################################
