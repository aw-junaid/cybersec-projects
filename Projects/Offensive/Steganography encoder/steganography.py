#!/usr/bin/env python3
"""
Steganography Tool - Hide secret data in images and audio files
Purpose: Covert communication, data protection, watermarking
Use: Hide sensitive information in carrier files
"""

from PIL import Image
import wave
import argparse
import os

class ImageSteganography:
    def __init__(self):
        self.STRING_TERMINATOR = "###END###"
    
    def text_to_binary(self, text):
        """Convert text to binary string"""
        return ''.join(format(ord(char), '08b') for char in text)
    
    def binary_to_text(self, binary_str):
        """Convert binary string to text"""
        text = ''
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            text += chr(int(byte, 2))
        return text
    
    def encode_image(self, image_path, secret_data, output_path):
        """
        Encode secret data into image using LSB (Least Significant Bit) technique
        """
        try:
            # Open image and convert to RGB
            image = Image.open(image_path)
            pixels = image.load()
            width, height = image.size
            
            # Convert secret data to binary
            binary_data = self.text_to_binary(secret_data + self.STRING_TERMINATOR)
            data_len = len(binary_data)
            
            # Check if image can hold the data
            if data_len > width * height * 3:
                raise ValueError("Image too small to hold the secret data")
            
            data_index = 0
            
            # Encode data in pixels
            for y in range(height):
                for x in range(width):
                    if data_index < data_len:
                        pixel = list(pixels[x, y])
                        
                        # Modify RGB values
                        for color in range(3):
                            if data_index < data_len:
                                # Clear LSB and set to data bit
                                pixel[color] = (pixel[color] & 0xFE) | int(binary_data[data_index])
                                data_index += 1
                        
                        pixels[x, y] = tuple(pixel)
                    else:
                        break
                else:
                    continue
                break
            
            # Save encoded image
            image.save(output_path)
            print(f"Data encoded successfully in {output_path}")
            return True
            
        except Exception as e:
            print(f"Encoding failed: {str(e)}")
            return False
    
    def decode_image(self, image_path):
        """
        Decode secret data from image
        """
        try:
            image = Image.open(image_path)
            pixels = image.load()
            width, height = image.size
            
            binary_data = ""
            
            # Extract LSB from each pixel
            for y in range(height):
                for x in range(width):
                    pixel = pixels[x, y]
                    for color in range(3):
                        # Get LSB from each color channel
                        binary_data += str(pixel[color] & 1)
            
            # Convert binary to text
            text = self.binary_to_text(binary_data)
            
            # Find terminator
            if self.STRING_TERMINATOR in text:
                secret_data = text.split(self.STRING_TERMINATOR)[0]
                print(f"Decoded data: {secret_data}")
                return secret_data
            else:
                print("No hidden data found or data corrupted")
                return None
                
        except Exception as e:
            print(f"Decoding failed: {str(e)}")
            return None

class AudioSteganography:
    def __init__(self):
        self.STRING_TERMINATOR = "###END###"
    
    def text_to_binary(self, text):
        """Convert text to binary string"""
        return ''.join(format(ord(char), '08b') for char in text)
    
    def binary_to_text(self, binary_str):
        """Convert binary string to text"""
        text = ''
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            text += chr(int(byte, 2))
        return text
    
    def encode_audio(self, audio_path, secret_data, output_path):
        """
        Encode secret data into audio file using LSB technique
        """
        try:
            audio = wave.open(audio_path, 'rb')
            params = audio.getparams()
            frames = audio.readframes(audio.getnframes())
            audio.close()
            
            # Convert frames to byte array
            frame_bytes = bytearray(list(frames))
            
            # Convert secret data to binary
            binary_data = self.text_to_binary(secret_data + self.STRING_TERMINATOR)
            data_len = len(binary_data)
            
            # Check if audio can hold the data
            if data_len > len(frame_bytes):
                raise ValueError("Audio file too small to hold the secret data")
            
            # Encode data in audio frames
            for i in range(data_len):
                frame_bytes[i] = (frame_bytes[i] & 0xFE) | int(binary_data[i])
            
            # Save encoded audio
            with wave.open(output_path, 'wb') as encoded_audio:
                encoded_audio.setparams(params)
                encoded_audio.writeframes(bytes(frame_bytes))
            
            print(f"Data encoded successfully in {output_path}")
            return True
            
        except Exception as e:
            print(f"Audio encoding failed: {str(e)}")
            return False
    
    def decode_audio(self, audio_path):
        """
        Decode secret data from audio file
        """
        try:
            audio = wave.open(audio_path, 'rb')
            frames = audio.readframes(audio.getnframes())
            audio.close()
            
            # Extract LSB from each frame
            frame_bytes = bytearray(list(frames))
            binary_data = ''.join(str(byte & 1) for byte in frame_bytes)
            
            # Convert binary to text
            text = self.binary_to_text(binary_data)
            
            # Find terminator
            if self.STRING_TERMINATOR in text:
                secret_data = text.split(self.STRING_TERMINATOR)[0]
                print(f"Decoded data: {secret_data}")
                return secret_data
            else:
                print("No hidden data found or data corrupted")
                return None
                
        except Exception as e:
            print(f"Audio decoding failed: {str(e)}")
            return None

def main():
    parser = argparse.ArgumentParser(description='Steganography Tool - Hide data in images and audio')
    parser.add_argument('--mode', choices=['encode', 'decode'], required=True, help='Operation mode')
    parser.add_argument('--type', choices=['image', 'audio'], required=True, help='Carrier file type')
    parser.add_argument('--input', required=True, help='Input file path')
    parser.add_argument('--output', help='Output file path (for encoding)')
    parser.add_argument('--data', help='Secret data to hide (for encoding)')
    
    args = parser.parse_args()
    
    if args.type == 'image':
        stego = ImageSteganography()
    else:
        stego = AudioSteganography()
    
    if args.mode == 'encode':
        if not args.data or not args.output:
            print("Error: --data and --output required for encoding")
            return
        stego.encode_image(args.input, args.data, args.output) if args.type == 'image' else stego.encode_audio(args.input, args.data, args.output)
    else:
        stego.decode_image(args.input) if args.type == 'image' else stego.decode_audio(args.input)

if __name__ == "__main__":
    main()
