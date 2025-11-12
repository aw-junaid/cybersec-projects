# Steganography Encoder/Decoder - Hide Data in Images/Audio

## How to Run the Code

### Python Version
```bash
# Install dependencies
pip install Pillow

# Encode secret message in image
python steganography.py --mode encode --type image --input original.png --output secret.png --data "My secret message"

# Decode from image
python steganography.py --mode decode --type image --input secret.png

# Encode in audio file
python steganography.py --mode encode --type audio --input original.wav --output secret.wav --data "Hidden audio message"

# Decode from audio
python steganography.py --mode decode --type audio --input secret.wav
```

### C Version
```bash
# Compile the C program
gcc -o steganography steganography.c -lm

# Encode secret message in PPM image
./steganography encode input.ppm output.ppm "Secret message"

# Decode from PPM image
./steganography decode secret.ppm
```

## Algorithm Explanation

### How LSB Steganography Works:

**Encoding Process:**
1. **Data Preparation**: Convert secret text to binary (ASCII → 8-bit binary)
2. **Carrier Analysis**: Check if carrier file (image/audio) has enough capacity
3. **LSB Replacement**: For each byte in carrier:
   - Clear the least significant bit (set to 0)
   - Replace with 1 bit from secret data
4. **Storage**: Modified carrier looks nearly identical but contains hidden data

**Decoding Process:**
1. **Bit Extraction**: Read LSB from each byte in carrier file
2. **Binary Reconstruction**: Combine extracted bits into binary string
3. **Text Conversion**: Convert 8-bit chunks back to ASCII characters
4. **Termination Check**: Look for end marker to identify complete message

### Technical Details:
- **Image**: Uses RGB channels (3 bits per pixel)
- **Audio**: Uses audio sample LSB modification
- **Capacity**: Image size × 3 (for RGB) bits maximum
- **Detection Resistance**: Visual/auditory changes are minimal

## Tool Purpose & Overview

### What is Steganography?
Steganography is the practice of concealing messages or information within other non-secret text or data. Unlike cryptography, which protects content, steganography focuses on hiding the existence of communication.

### Cybersecurity Context: **Offensive Security**

**Primary Uses:**
1. **Covert Communication**: Hide messages in innocent-looking files
2. **Data Exfiltration**: Secretly extract data from secured environments
3. **Watermarking**: Embed ownership information in digital media
4. **Command & Control**: Hide C2 communications in normal traffic

### Real-World Applications:
- **Law Enforcement**: Undercover communications
- **Military**: Secret message transmission
- **Digital Rights**: Copyright protection through watermarks
- **Security Research**: Testing data leakage prevention systems

### Legal & Ethical Considerations:
- **Legal**: Use only with proper authorization
- **Ethical**: Never use for malicious purposes
- **Educational**: Understand for defensive protection
- **Detection**: Learn to identify steganographic content

### Detection & Countermeasures:
- **Statistical Analysis**: Detect LSB pattern anomalies
- **Steganalysis Tools**: Specialized software to find hidden data
- **File Integrity Checks**: Monitor for unexpected modifications
- **Network Monitoring**: Detect unusual data patterns in transmissions

