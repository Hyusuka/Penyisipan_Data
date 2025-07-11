import cv2
import numpy as np
import logging
import os

logger = logging.getLogger(__name__)

class LSBSteganography:
    @staticmethod
    def embed(image: np.ndarray, data: bytes, output_path: str) -> bool:
        """Embed data into image and save to output_path"""
        try:
            length = len(data).to_bytes(4, 'big')
            binary_data = ''.join(format(byte, '08b') for byte in length + data)
            
            if len(binary_data) > image.size * 3:
                raise ValueError("Data terlalu besar untuk gambar ini")

            flat_img = image.reshape(-1)
            for i in range(len(binary_data)):
                flat_img[i] = (flat_img[i] & 0xFE) | int(binary_data[i])

            return cv2.imwrite(output_path, image.reshape(image.shape), [cv2.IMWRITE_PNG_COMPRESSION, 0])
        except Exception as e:
            logger.error(f"Embedding error: {str(e)}")
            if os.path.exists(output_path):
                os.remove(output_path)
            return False

    @staticmethod
    def extract(image: np.ndarray) -> bytes:
        """Extract data from stego image"""
        try:
            flat_img = image.reshape(-1)
            length_bits = ''.join(str(flat_img[i] & 1) for i in range(32))
            length = int(length_bits, 2)
            
            data_bits = ''.join(str(flat_img[i] & 1) for i in range(32, 32 + length * 8))
            return bytes(int(data_bits[i:i+8], 2) for i in range(0, len(data_bits), 8))
        except Exception as e:
            logger.error(f"Extraction error: {str(e)}")
            raise