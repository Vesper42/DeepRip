# DeepRip - Modern iOS App Extractor

A powerful, cross-platform tool for extracting iOS applications from jailbroken devices using Frida. Compatible with iOS versions up to 16.7.11 and supports multiple Linux distributions.

## 🚀 Features

- **iOS Compatibility**: Supports iOS up to 16.7.11
- **Cross-Platform**: Works on Ubuntu, Debian, CentOS, RHEL, Fedora, Arch Linux, Manjaro, and EndeavourOS
- **Automatic App Detection**: Find apps by name or bundle identifier
- **Memory Dumping**: Extracts decrypted application binaries from memory
- **IPA Generation**: Automatically creates installable IPA files
- **SSH Integration**: Secure file transfer via SSH/SCP
- **Comprehensive Testing**: Built-in system validation and diagnostics
- **User-Friendly**: Colored output and progress indicators

## 📋 Prerequisites

### Device Requirements
- Jailbroken iOS device (iOS ≤ 16.7.11)
- Frida server installed on device (available in Cydia/Sileo)
- SSH access enabled on device
- USB connection to host computer

### System Requirements
- Linux-based operating system
- Python 3.7 or higher
- USB connection capabilities
- Root/sudo access for initial setup

## 🛠 Installation

### Quick Setup

1. **Clone the repository**:
```bash
git clone <repository-url>
cd deeprip
```

2. **Run the automated setup**:
```bash
chmod +x setup_dependencies.sh
./setup_dependencies.sh
```

3. **Test your installation**:
```bash
python3 test_system.py
```

### Manual Installation

If you prefer manual installation or need to troubleshoot:

1. **Install system dependencies**:

   **Ubuntu/Debian**:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-dev build-essential \
                    libssl-dev libffi-dev usbmuxd openssh-client git curl
   ```

   **CentOS/RHEL/Rocky/AlmaLinux**:
   ```bash
   sudo dnf install python3 python3-pip python3-devel gcc gcc-c++ make \
                    openssl-devel libffi-devel libusbmuxd libusbmuxd-utils
   ```

   **Fedora**:
   ```bash
   sudo dnf install python3 python3-pip python3-devel gcc gcc-c++ make \
                    openssl-devel libffi-devel libusbmuxd libusbmuxd-utils
   ```

   **Arch Linux/Manjaro/EndeavourOS**:
   ```bash
   sudo pacman -S python python-pip base-devel openssl libffi usbmuxd openssh
   ```

2. **Install Python dependencies**:
```bash
pip3 install -r requirements.txt
```

## 🔧 Configuration

The tool automatically creates a configuration file at `~/.frida_ios_dump_config`. You can customize settings:

```ini
[DEFAULT]
ssh_host = 127.0.0.1
ssh_port = 2222
ssh_user = mobile
ssh_pass = alpine
output_dir = ./dumps
temp_dir = /tmp/frida_dump
frida_server_port = 27042
max_retries = 3
timeout = 30
```

## 📱 Device Setup

### 1. Jailbreak Requirements
- Device must be jailbroken (checkra1n, unc0ver, Taurine, etc.)
- Compatible with iOS versions up to 16.7.11

### 2. Install Frida Server
Install Frida server from your package manager:
- **Cydia**: Add `https://build.frida.re` as a source, install "Frida"
- **Sileo**: Search for "Frida" and install

### 3. Enable SSH Access
Most jailbreaks enable SSH by default. If not:
- Install OpenSSH from Cydia/Sileo
- Default credentials: `mobile`/`alpine` (change these for security!)

### 4. Connect via USB
```bash
# Install iproxy (usually included with usbmuxd)
# Start port forwarding
iproxy 2222 22
```

## 💻 Usage

### Basic Commands

**List all installed applications**:
```bash
python3 deeprip.py -l
```

**Dump an application by name**:
```bash
python3 deeprip.py "App Name"
```

**Dump an application by bundle identifier**:
```bash
python3 deeprip.py com.example.app
```

**Use custom configuration**:
```bash
python3 deeprip.py -c custom_config.ini "App Name"
```

**Specify output directory**:
```bash
python3 deeprip.py -o /path/to/dumps "App Name"
```

### System Testing

**Run comprehensive system tests**:
```bash
python3 test_system.py
```

**Quick validation**:
```bash
python3 test_system.py --quick
```

**Fix common permission issues**:
```bash
python3 test_system.py --fix-permissions
```

**Show device information**:
```bash
python3 test_system.py --device-info
```

## 🔍 Example Workflow

1. **Prepare your system**:
```bash
./setup_dependencies.sh
python3 test_system.py
```

2. **Connect your device**:
```bash
# In terminal 1: Start port forwarding
iproxy 2222 22

# In terminal 2: Test connection
ssh mobile@127.0.0.1 -p 2222
```

3. **List and dump applications**:
```bash
# See what's installed
python3 deeprip.py -l

# Dump a specific app
python3 deeprip.py "Instagram"
```

4. **Find your decrypted IPA**:
```bash
ls -la dumps/Instagram_*/
```

## 📂 Output Structure

Dumped applications create the following structure:
```
dumps/
└── AppName_1234567890/
    ├── AppName_decrypted.ipa    # Ready-to-install IPA
    ├── AppName                  # Main executable
    ├── Framework1.dylib         # App frameworks
    ├── Framework2.dylib
    └── ...
```

## 🐛 Troubleshooting

### Common Issues

**"No USB devices found"**:
- Ensure device is connected via USB
- Check if device is trusted (unlock and tap "Trust")
- Restart usbmuxd: `sudo systemctl restart usbmuxd`

**"SSH connection failed"**:
- Verify iproxy is running: `iproxy 2222 22`
- Check SSH credentials (default: mobile/alpine)
- Try connecting manually: `ssh mobile@127.0.0.1 -p 2222`

**"Frida server not responding"**:
- Ensure Frida is installed on device
- Check if frida-server is running: `ps aux | grep frida-server`
- Restart Frida server on device

**"Permission denied" errors**:
- Add user to plugdev group: `sudo usermod -a -G plugdev $USER`
- Log out and back in for group changes to take effect
- Run permission fix: `python3 test_system.py --fix-permissions`

### Advanced Troubleshooting

**Enable verbose debugging**:
```bash
python3 deeprip.py -v "App Name"
```

**Check system compatibility**:
```bash
python3 test_system.py --device-info
```

**Manual Frida connection test**:
```bash
frida-ls-devices
frida-ps -U
```

## 🛡 Security Considerations

- **Change default SSH credentials** on your device
- **Use secure networks** when transferring dumps
- **Respect app store terms** and only dump apps you own
- **Keep your tools updated** for latest security patches

## 📝 Legal Notice

This tool is intended for educational purposes and legitimate security research only. Users are responsible for complying with:

- App Store terms of service
- Local copyright laws
- Software licensing agreements
- Applicable regulations in their jurisdiction

**Only dump applications that you own or have explicit permission to analyze.**

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Development Setup

```bash
git clone <your-fork>
cd deeprip
./setup_dependencies.sh
python3 test_system.py
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [Frida](https://frida.re/) - Dynamic instrumentation toolkit
- [checkra1n](https://checkra.in/) - iOS jailbreak tool
- [unc0ver](https://unc0ver.dev/) - iOS jailbreak tool
- The jailbreak community for making iOS research possible

## 🗺 Roadmap

### Version 2.0 - Easy Distribution & Cross-Platform
- [ ] **Docker Support**: Complete containerized solution
  ```bash
  docker run --privileged -v /dev/bus/usb:/dev/bus/usb deeprip:latest
  ```
- [ ] **PyPI Package**: Install via pip globally
  ```bash
  pip install deeprip
  deeprip --list
  ```
- [ ] **Android Support**: Cross-platform APK extraction from Android devices
  ```bash
  deeprip --platform android "com.example.app"
  deeprip --platform ios "com.example.app" 
  ```

### Community Goals
- [ ] **Cross-platform testing** on 10+ Linux distributions
- [ ] **Community plugins** and extensions

*DeepRip aims to be the go-to tool for mobile app extraction - starting with iOS and expanding to Android.*

## 📞 Support

- **GitHub Issues**: Report bugs and request features

---

**Made with ❤️ for the iOS security research community**