#!/bin/bash

# DeepRip - iOS App Extractor - Dependency Setup Script
# Compatible with: Ubuntu, Debian, CentOS, RedHat, Fedora, Arch Linux, Manjaro, EndeavourOS
# Supports iOS up to 16.7.11 on jailbroken devices

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    else
        print_error "Cannot detect Linux distribution"
        exit 1
    fi
    
    print_status "Detected distribution: $DISTRO"
}

install_python_deps() {
    print_status "Installing Python dependencies for DeepRip..."
    
    # Ensure we have pip
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 not found. Please install Python 3 and pip first."
        exit 1
    fi
    
    # Install required Python packages
    pip3 install --user --upgrade \
        frida==16.7.10 \
        frida-tools==13.6.0 \
        paramiko \
        scp \
        biplist \
        requests \
        colorama \
        tqdm
    
    print_success "Python dependencies installed"
}

install_system_deps() {
    case $DISTRO in
        ubuntu|debian)
            print_status "Installing dependencies for Ubuntu/Debian..."
            sudo apt update
            sudo apt install -y \
                python3 \
                python3-pip \
                python3-dev \
                build-essential \
                libssl-dev \
                libffi-dev \
                usbmuxd \
                openssh-client \
                git \
                curl \
                zip \
                unzip
            
            # Install libusbmuxd-tools for newer Ubuntu versions
            if apt list --installed libusbmuxd-tools 2>/dev/null | grep -q libusbmuxd-tools; then
                sudo apt install -y libusbmuxd-tools
            fi
            ;;
            
        centos|rhel|rocky|almalinux)
            print_status "Installing dependencies for CentOS/RHEL/Rocky/AlmaLinux..."
            if command -v dnf &> /dev/null; then
                PKG_MANAGER="dnf"
            else
                PKG_MANAGER="yum"
            fi
            
            sudo $PKG_MANAGER install -y epel-release
            sudo $PKG_MANAGER groupinstall -y "Development Tools"
            sudo $PKG_MANAGER install -y \
                python3 \
                python3-pip \
                python3-devel \
                openssl-devel \
                libffi-devel \
                libusbmuxd \
                libusbmuxd-utils \
                openssh-clients \
                git \
                curl \
                zip \
                unzip
            ;;
            
        fedora)
            print_status "Installing dependencies for Fedora..."
            sudo dnf install -y \
                python3 \
                python3-pip \
                python3-devel \
                gcc \
                gcc-c++ \
                make \
                openssl-devel \
                libffi-devel \
                libusbmuxd \
                libusbmuxd-utils \
                openssh-clients \
                git \
                curl \
                zip \
                unzip
            ;;
            
        arch|manjaro|endeavouros)
            print_status "Installing dependencies for Arch Linux/Manjaro/EndeavourOS..."
            sudo pacman -Sy --noconfirm \
                python \
                python-pip \
                base-devel \
                openssl \
                libffi \
                usbmuxd \
                openssh \
                git \
                curl \
                zip \
                unzip
            ;;
            
        *)
            print_warning "Unsupported distribution: $DISTRO"
            print_warning "Please install the following packages manually:"
            echo "  - python3, python3-pip, python3-dev"
            echo "  - build-essential/development tools"
            echo "  - openssl-dev, libffi-dev"
            echo "  - usbmuxd, openssh-client"
            echo "  - git, curl, zip, unzip"
            ;;
    esac
}

setup_usbmuxd() {
    print_status "Setting up usbmuxd for iOS device connection..."
    
    # Start and enable usbmuxd service
    if systemctl is-enabled usbmuxd &>/dev/null; then
        sudo systemctl enable usbmuxd
        sudo systemctl start usbmuxd
    fi
    
    # Add user to plugdev group if it exists
    if getent group plugdev > /dev/null 2>&1; then
        sudo usermod -a -G plugdev $USER
        print_warning "Added user to plugdev group. Please log out and log back in for changes to take effect."
    fi
    
    print_success "usbmuxd setup completed"
}

create_config() {
    print_status "Creating DeepRip configuration file..."
    
    cat > ~/.deeprip_config << 'EOF'
# DeepRip Configuration
[DEFAULT]
ssh_host = 127.0.0.1
ssh_port = 2222
ssh_user = mobile
ssh_pass = alpine
output_dir = ./dumps
temp_dir = /tmp/deeprip_dump
frida_server_port = 27042
max_retries = 3
timeout = 30

[DEVICE]
# Default SSH credentials for jailbroken iOS devices
# Change these if you've modified your device's credentials
default_user = mobile
default_pass = alpine
root_user = root
root_pass = alpine

[PATHS]
# Common iOS application paths
app_path = /var/containers/Bundle/Application
system_app_path = /Applications
frameworks_path = /System/Library/Frameworks
private_frameworks_path = /System/Library/PrivateFrameworks
EOF
    
    print_success "Configuration file created at ~/.deeprip_config"
}

install_additional_tools() {
    print_status "Installing additional useful tools..."
    
    # Install iproxy if not available
    if ! command -v iproxy &> /dev/null; then
        case $DISTRO in
            ubuntu|debian)
                sudo apt install -y libusbmuxd-tools
                ;;
            arch|manjaro|endeavouros)
                # iproxy is part of usbmuxd package
                ;;
            *)
                print_warning "iproxy might not be available. You may need to install it manually."
                ;;
        esac
    fi
    
    # Install objection for additional iOS testing
    pip3 install --user objection
    
    print_success "Additional tools installed"
}

check_installation() {
    print_status "Verifying DeepRip installation..."
    
    FAILED=0
    
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 not found"
        FAILED=1
    fi
    
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 not found"
        FAILED=1
    fi
    
    if ! python3 -c "import frida" 2>/dev/null; then
        print_error "Frida Python module not found"
        FAILED=1
    fi
    
    if ! command -v frida &> /dev/null; then
        print_error "Frida CLI not found"
        FAILED=1
    fi
    
    if [ $FAILED -eq 0 ]; then
        print_success "All dependencies installed successfully!"
        echo ""
        echo -e "${GREEN}Next steps:${NC}"
        echo "1. Connect your jailbroken iOS device"
        echo "2. Install Frida server on your device from Cydia/Sileo"
        echo "3. Run: iproxy 2222 22 (in a separate terminal)"
        echo "4. Run: python3 deeprip.py <app_name_or_bundle_id>"
        echo ""
        echo -e "${YELLOW}Note:${NC} If you added to plugdev group, please log out and back in."
    else
        print_error "Some dependencies failed to install. Please check the errors above."
        exit 1
    fi
}

main() {
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}      DeepRip - Dependency Setup       ${NC}"
    echo -e "${BLUE}    Modern iOS App Extractor Setup     ${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_error "Please don't run this script as root"
        exit 1
    fi
    
    detect_distro
    install_system_deps
    install_python_deps
    setup_usbmuxd
    create_config
    install_additional_tools
    check_installation
    
    print_success "DeepRip setup completed successfully!"
}

main "$@"