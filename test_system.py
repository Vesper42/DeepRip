#!/usr/bin/env python3
"""
System Testing and Validation Script for DeepRip - Modern iOS App Extractor
Tests all components and provides diagnostic information
"""

import os
import sys
import subprocess
import importlib
import platform
import socket
import time
from pathlib import Path
from typing import Dict, List, Tuple, Optional

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = ""
    class Style:
        RESET_ALL = ""

class SystemTester:
    def __init__(self):
        """Initialize the system tester."""
        self.results = []
        self.errors = []
        self.warnings = []
        
    def print_status(self, message: str, level: str = "info"):
        """Print colored status messages."""
        if not COLORS_AVAILABLE:
            print(f"[{level.upper()}] {message}")
            return
            
        colors = {
            "info": Fore.BLUE,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "header": Fore.CYAN
        }
        
        prefix = {
            "info": "[INFO]",
            "success": "[✓]",
            "warning": "[!]",
            "error": "[✗]",
            "header": "[>>>]"
        }
        
        color = colors.get(level, "")
        pre = prefix.get(level, "[INFO]")
        print(f"{color}{pre} {message}{Style.RESET_ALL}")
        
    def run_command(self, command: str, capture_output: bool = True) -> Tuple[bool, str]:
        """Run a shell command and return success status and output."""
        try:
            if capture_output:
                result = subprocess.run(
                    command, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=30
                )
                return result.returncode == 0, result.stdout.strip()
            else:
                result = subprocess.run(command, shell=True, timeout=30)
                return result.returncode == 0, ""
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, f"Command failed: {str(e)}"
    
    def test_system_info(self) -> Dict:
        """Test and gather system information."""
        self.print_status("Gathering system information...", "header")
        
        info = {
            "os": platform.system(),
            "os_version": platform.release(),
            "distribution": "Unknown",
            "architecture": platform.machine(),
            "python_version": sys.version,
            "user": os.getenv("USER", "unknown")
        }
        
        # Detect Linux distribution
        if info["os"] == "Linux":
            try:
                with open('/etc/os-release', 'r') as f:
                    os_release = f.read()
                    for line in os_release.split('\n'):
                        if line.startswith('PRETTY_NAME='):
                            info["distribution"] = line.split('=')[1].strip('"')
                            break
            except:
                pass
        
        self.print_status(f"OS: {info['os']} {info['os_version']}", "info")
        self.print_status(f"Distribution: {info['distribution']}", "info")
        self.print_status(f"Architecture: {info['architecture']}", "info")
        self.print_status(f"Python: {sys.version.split()[0]}", "info")
        
        return info
    
    def test_python_dependencies(self) -> bool:
        """Test Python dependencies."""
        self.print_status("Testing Python dependencies...", "header")
        
        required_modules = [
            ("frida", "frida-tools"),
            ("paramiko", "paramiko"),
            ("scp", "scp"),
            ("biplist", "biplist"),
            ("requests", "requests"),
            ("colorama", "colorama"),
            ("tqdm", "tqdm")
        ]
        
        all_good = True
        
        for module_name, package_name in required_modules:
            try:
                module = importlib.import_module(module_name)
                version = getattr(module, '__version__', 'unknown')
                self.print_status(f"{package_name}: {version}", "success")
            except ImportError:
                self.print_status(f"{package_name}: NOT FOUND", "error")
                self.errors.append(f"Missing Python package: {package_name}")
                all_good = False
        
        return all_good
    
    def test_system_tools(self) -> bool:
        """Test required system tools."""
        self.print_status("Testing system tools...", "header")
        
        required_tools = [
            ("python3", "Python 3 interpreter"),
            ("pip3", "Python package manager"),
            ("ssh", "SSH client"),
            ("frida", "Frida CLI tool"),
            ("iproxy", "USB multiplexer proxy")
        ]
        
        all_good = True
        
        for tool, description in required_tools:
            success, output = self.run_command(f"which {tool}")
            if success:
                # Get version if possible
                version_success, version = self.run_command(f"{tool} --version 2>/dev/null || {tool} -V 2>/dev/null")
                version_str = version.split('\n')[0] if version_success else "unknown version"
                self.print_status(f"{description}: {version_str}", "success")
            else:
                self.print_status(f"{description}: NOT FOUND", "error")
                self.errors.append(f"Missing system tool: {tool}")
                all_good = False
        
        return all_good
    
    def test_usbmuxd_service(self) -> bool:
        """Test usbmuxd service status."""
        self.print_status("Testing usbmuxd service...", "header")
        
        # Check if usbmuxd is running
        success, output = self.run_command("systemctl is-active usbmuxd 2>/dev/null")
        if success and "active" in output:
            self.print_status("usbmuxd service: ACTIVE", "success")
            return True
        else:
            # Try alternative methods
            success, output = self.run_command("ps aux | grep usbmuxd | grep -v grep")
            if success and output:
                self.print_status("usbmuxd process: RUNNING", "success")
                return True
            else:
                self.print_status("usbmuxd service: NOT RUNNING", "warning")
                self.warnings.append("usbmuxd service is not running")
                return False
    
    def test_device_connection(self) -> bool:
        """Test iOS device connection."""
        self.print_status("Testing iOS device connection...", "header")
        
        # Test Frida device enumeration
        success, output = self.run_command("frida-ls-devices")
        if success:
            devices = output.split('\n')[1:]  # Skip header line
            usb_devices = [line for line in devices if 'usb' in line.lower()]
            
            if usb_devices:
                self.print_status(f"Found {len(usb_devices)} USB device(s)", "success")
                for device in usb_devices[:3]:  # Show first 3 devices
                    self.print_status(f"  Device: {device.strip()}", "info")
                return True
            else:
                self.print_status("No USB devices found", "warning")
                self.warnings.append("No iOS devices detected via USB")
                return False
        else:
            self.print_status("Failed to enumerate devices", "error")
            self.errors.append("Cannot enumerate Frida devices")
            return False
    
    def test_ssh_connection(self) -> bool:
        """Test SSH connection to iOS device."""
        self.print_status("Testing SSH connection...", "header")
        
        # Check if iproxy is running
        success, output = self.run_command("ps aux | grep 'iproxy.*2222.*22' | grep -v grep")
        if not success or not output:
            self.print_status("iproxy not running (2222 -> 22)", "warning")
            self.warnings.append("iproxy is not running. Start with: iproxy 2222 22")
            return False
        else:
            self.print_status("iproxy is running", "success")
        
        # Test SSH connection
        ssh_cmd = "ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no mobile@127.0.0.1 -p 2222 'echo SSH_TEST_OK' 2>/dev/null"
        success, output = self.run_command(ssh_cmd)
        
        if success and "SSH_TEST_OK" in output:
            self.print_status("SSH connection: SUCCESS", "success")
            return True
        else:
            self.print_status("SSH connection: FAILED", "warning")
            self.warnings.append("Cannot connect via SSH. Check device connection and credentials")
            return False
    
    def test_frida_server(self) -> bool:
        """Test Frida server on device."""
        self.print_status("Testing Frida server on device...", "header")
        
        # Try to connect to Frida server
        try:
            import frida
            device_manager = frida.get_device_manager()
            devices = device_manager.enumerate_devices()
            
            usb_devices = [d for d in devices if d.type == 'usb']
            if usb_devices:
                device = usb_devices[0]
                try:
                    # Try to enumerate processes (this requires Frida server)
                    processes = device.enumerate_processes()
                    self.print_status(f"Frida server: RUNNING ({len(processes)} processes)", "success")
                    return True
                except Exception as e:
                    self.print_status(f"Frida server: NOT RESPONDING ({str(e)})", "error")
                    self.errors.append("Frida server is not running on device")
                    return False
            else:
                self.print_status("No USB devices for Frida test", "warning")
                return False
                
        except Exception as e:
            self.print_status(f"Frida test failed: {str(e)}", "error")
            self.errors.append(f"Frida connection error: {str(e)}")
            return False
    
    def test_permissions(self) -> bool:
        """Test file permissions and access."""
        self.print_status("Testing file permissions...", "header")
        
        all_good = True
        
        # Test write access to common directories
        test_dirs = [
            ("./", "Current directory"),
            ("./dumps", "Dumps directory"),
            ("/tmp", "Temporary directory")
        ]
        
        for test_dir, description in test_dirs:
            try:
                os.makedirs(test_dir, exist_ok=True)
                test_file = os.path.join(test_dir, f"test_write_{int(time.time())}")
                
                with open(test_file, 'w') as f:
                    f.write("test")
                
                os.remove(test_file)
                self.print_status(f"Write access to {description}: OK", "success")
                
            except Exception as e:
                self.print_status(f"Write access to {description}: FAILED", "error")
                self.errors.append(f"Cannot write to {test_dir}: {str(e)}")
                all_good = False
        
        # Test user groups
        success, output = self.run_command("groups")
        if success:
            groups = output.split()
            if "plugdev" in groups:
                self.print_status("User in plugdev group: YES", "success")
            else:
                self.print_status("User in plugdev group: NO", "warning")
                self.warnings.append("User not in plugdev group. May cause USB access issues")
        
        return all_good
    
    def test_configuration(self) -> bool:
        """Test configuration file."""
        self.print_status("Testing DeepRip configuration...", "header")
        
        config_path = os.path.expanduser("~/.deeprip_config")
        
        if os.path.exists(config_path):
            self.print_status(f"Configuration file: FOUND", "success")
            
            try:
                with open(config_path, 'r') as f:
                    config_content = f.read()
                
                # Basic validation
                required_sections = ["DEFAULT"]
                required_keys = ["ssh_host", "ssh_port", "ssh_user", "output_dir"]
                
                all_found = True
                for key in required_keys:
                    if key not in config_content:
                        self.print_status(f"Missing config key: {key}", "warning")
                        all_found = False
                
                if all_found:
                    self.print_status("Configuration validation: PASSED", "success")
                    return True
                else:
                    self.warnings.append("Configuration file is incomplete")
                    return False
                    
            except Exception as e:
                self.print_status(f"Configuration read error: {str(e)}", "error")
                self.errors.append(f"Cannot read configuration: {str(e)}")
                return False
        else:
            self.print_status("Configuration file: NOT FOUND", "warning")
            self.warnings.append("Configuration file not found. Will use defaults")
            return False
    
    def test_deeprip_script(self) -> bool:
        """Test if DeepRip main script exists and is executable."""
        self.print_status("Testing DeepRip main script...", "header")
        
        script_paths = ["deeprip.py", "./deeprip.py"]
        script_found = False
        
        for script_path in script_paths:
            if os.path.exists(script_path):
                script_found = True
                self.print_status(f"DeepRip script found: {script_path}", "success")
                
                # Test if it's executable
                if os.access(script_path, os.X_OK):
                    self.print_status("Script is executable", "success")
                else:
                    self.print_status("Script is not executable", "warning")
                    self.warnings.append(f"Run: chmod +x {script_path}")
                
                # Test basic syntax
                success, output = self.run_command(f"python3 -m py_compile {script_path}")
                if success:
                    self.print_status("Script syntax: VALID", "success")
                else:
                    self.print_status("Script syntax: INVALID", "error")
                    self.errors.append(f"Python syntax error in {script_path}")
                    return False
                break
        
        if not script_found:
            self.print_status("DeepRip script: NOT FOUND", "error")
            self.errors.append("deeprip.py not found in current directory")
            return False
        
        return True
    
    def provide_recommendations(self):
        """Provide recommendations based on test results."""
        self.print_status("Recommendations and fixes...", "header")
        
        if self.errors:
            self.print_status("Critical issues found:", "error")
            for i, error in enumerate(self.errors, 1):
                print(f"  {i}. {error}")
            
            print(f"\n{Fore.RED}Fix critical issues before proceeding:{Style.RESET_ALL}")
            print("• Run: ./setup_dependencies.sh")
            print("• Install missing packages manually")
            print("• Check device connection")
            print("• Ensure deeprip.py is in current directory")
            
        if self.warnings:
            print(f"\n{Fore.YELLOW}Warnings (may cause issues):{Style.RESET_ALL}")
            for i, warning in enumerate(self.warnings, 1):
                print(f"  {i}. {warning}")
            
            print(f"\n{Fore.YELLOW}Recommended fixes:{Style.RESET_ALL}")
            print("• Start iproxy: iproxy 2222 22")
            print("• Install Frida server on device")
            print("• Add user to plugdev group: sudo usermod -a -G plugdev $USER")
            print("• Enable SSH on iOS device")
            print("• Make script executable: chmod +x deeprip.py")
    
    def run_all_tests(self) -> bool:
        """Run all system tests."""
        print(f"{Fore.CYAN}{'='*60}")
        print(f"         DeepRip - System Test & Validation")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        tests = [
            ("System Information", self.test_system_info),
            ("Python Dependencies", self.test_python_dependencies),
            ("System Tools", self.test_system_tools),
            ("USB Service", self.test_usbmuxd_service),
            ("Device Connection", self.test_device_connection),
            ("SSH Connection", self.test_ssh_connection),
            ("Frida Server", self.test_frida_server),
            ("File Permissions", self.test_permissions),
            ("Configuration", self.test_configuration),
            ("DeepRip Script", self.test_deeprip_script)
        ]
        
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests:
            try:
                if test_name == "System Information":
                    test_func()  # This one returns dict, not bool
                    passed += 1
                else:
                    result = test_func()
                    if result:
                        passed += 1
            except Exception as e:
                self.print_status(f"Test '{test_name}' crashed: {str(e)}", "error")
                self.errors.append(f"Test crash: {test_name}")
            
            print()  # Add spacing between tests
        
        # Summary
        print(f"{Fore.CYAN}{'='*60}")
        print(f"                    TEST SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        print(f"Tests passed: {Fore.GREEN}{passed}/{total}{Style.RESET_ALL}")
        print(f"Errors: {Fore.RED}{len(self.errors)}{Style.RESET_ALL}")
        print(f"Warnings: {Fore.YELLOW}{len(self.warnings)}{Style.RESET_ALL}")
        
        if len(self.errors) == 0 and len(self.warnings) <= 2:
            print(f"\n{Fore.GREEN}✅ DeepRip is ready for iOS app extraction!{Style.RESET_ALL}")
            success = True
        elif len(self.errors) == 0:
            print(f"\n{Fore.YELLOW}⚠️  DeepRip mostly ready, but check warnings{Style.RESET_ALL}")
            success = True
        else:
            print(f"\n{Fore.RED}❌ DeepRip has critical issues{Style.RESET_ALL}")
            success = False
        
        print()
        self.provide_recommendations()
        
        return success


def main():
    """Main entry point for the test script."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="System Testing and Validation for DeepRip - Modern iOS App Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 test_system.py                    # Run all tests
  python3 test_system.py --quick           # Run essential tests only
  python3 test_system.py --fix-permissions # Fix common permission issues
  python3 test_system.py --device-info     # Show device information only

This script will test your DeepRip setup and provide recommendations
for fixing any issues before attempting to extract iOS applications.
        """)
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Run only essential tests (faster)'
    )
    
    parser.add_argument(
        '--fix-permissions',
        action='store_true',
        help='Attempt to fix common permission issues'
    )
    
    parser.add_argument(
        '--device-info',
        action='store_true',
        help='Show detailed device information'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        global COLORS_AVAILABLE
        COLORS_AVAILABLE = False
    
    tester = SystemTester()
    
    if args.fix_permissions:
        fix_permissions()
        return
    
    if args.device_info:
        show_device_info()
        return
    
    # Run tests
    if args.quick:
        success = run_quick_tests(tester)
    else:
        success = tester.run_all_tests()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


def fix_permissions():
    """Attempt to fix common permission issues."""
    print(f"{Fore.CYAN}Fixing common permission issues for DeepRip...{Style.RESET_ALL}\n")
    
    fixes = [
        ("Add user to plugdev group", "sudo usermod -a -G plugdev $USER"),
        ("Set udev rules for iOS devices", create_udev_rules),
        ("Start/enable usbmuxd service", "sudo systemctl enable --now usbmuxd"),
        ("Create dumps directory", "mkdir -p ./dumps && chmod 755 ./dumps"),
        ("Fix Python module permissions", "pip3 install --user --upgrade frida-tools"),
        ("Make DeepRip executable", "chmod +x deeprip.py")
    ]
    
    for description, command in fixes:
        print(f"{Fore.BLUE}[FIXING]{Style.RESET_ALL} {description}")
        
        if callable(command):
            try:
                command()
                print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {description}")
            except Exception as e:
                print(f"{Fore.RED}[FAILED]{Style.RESET_ALL} {description}: {e}")
        else:
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {description}")
                else:
                    print(f"{Fore.RED}[FAILED]{Style.RESET_ALL} {description}: {result.stderr}")
            except Exception as e:
                print(f"{Fore.RED}[FAILED]{Style.RESET_ALL} {description}: {e}")
    
    print(f"\n{Fore.YELLOW}Note: You may need to log out and back in for group changes to take effect.{Style.RESET_ALL}")


def create_udev_rules():
    """Create udev rules for iOS devices."""
    udev_rules = """# iOS Device Rules for DeepRip - Modern iOS App Extractor
# Place this file in /etc/udev/rules.d/39-ios-device.rules

# iPhone/iPad/iPod Touch
SUBSYSTEM=="usb", ATTR{idVendor}=="05ac", ATTR{idProduct}=="12a*", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="05ac", ATTR{idProduct}=="129*", MODE="0666", GROUP="plugdev"

# Reload rules after creating this file:
# sudo udevadm control --reload-rules
# sudo udevadm trigger
"""
    
    rules_path = "/etc/udev/rules.d/39-ios-device.rules"
    
    try:
        # Check if running with sudo
        if os.geteuid() != 0:
            print(f"Creating udev rules requires sudo. Run:")
            print(f"sudo tee {rules_path} << 'EOF'")
            print(udev_rules)
            print("EOF")
            print("sudo udevadm control --reload-rules")
            print("sudo udevadm trigger")
        else:
            with open(rules_path, 'w') as f:
                f.write(udev_rules)
            
            subprocess.run("udevadm control --reload-rules", shell=True)
            subprocess.run("udevadm trigger", shell=True)
            
    except Exception as e:
        raise Exception(f"Failed to create udev rules: {e}")


def show_device_info():
    """Show detailed device information."""
    print(f"{Fore.CYAN}Detailed Device Information for DeepRip{Style.RESET_ALL}\n")
    
    # USB devices
    print(f"{Fore.BLUE}USB Devices:{Style.RESET_ALL}")
    subprocess.run("lsusb | grep -i apple || echo 'No Apple devices found'", shell=True)
    print()
    
    # Frida devices
    print(f"{Fore.BLUE}Frida Devices:{Style.RESET_ALL}")
    subprocess.run("frida-ls-devices 2>/dev/null || echo 'Frida not available'", shell=True)
    print()
    
    # Network connections (iproxy)
    print(f"{Fore.BLUE}Network Connections (iproxy):{Style.RESET_ALL}")
    subprocess.run("netstat -tlnp 2>/dev/null | grep :2222 || echo 'iproxy not running on port 2222'", shell=True)
    print()
    
    # iOS device info via SSH (if available)
    print(f"{Fore.BLUE}iOS Device Info (via SSH):{Style.RESET_ALL}")
    ssh_commands = [
        ("Device Model", "ssh -o ConnectTimeout=3 mobile@127.0.0.1 -p 2222 'uname -m' 2>/dev/null"),
        ("iOS Version", "ssh -o ConnectTimeout=3 mobile@127.0.0.1 -p 2222 'sw_vers -productVersion' 2>/dev/null"),
        ("Device Name", "ssh -o ConnectTimeout=3 mobile@127.0.0.1 -p 2222 'hostname' 2>/dev/null"),
        ("Frida Server", "ssh -o ConnectTimeout=3 mobile@127.0.0.1 -p 2222 'ps aux | grep frida-server | grep -v grep' 2>/dev/null")
    ]
    
    for desc, cmd in ssh_commands:
        print(f"  {desc}: ", end="")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            print(result.stdout.strip())
        else:
            print("Not available")


def run_quick_tests(tester):
    """Run only essential tests for quick validation."""
    print(f"{Fore.CYAN}Running Quick DeepRip System Tests...{Style.RESET_ALL}\n")
    
    essential_tests = [
        ("Python Dependencies", tester.test_python_dependencies),
        ("System Tools", tester.test_system_tools),
        ("Device Connection", tester.test_device_connection),
        ("SSH Connection", tester.test_ssh_connection),
        ("DeepRip Script", tester.test_deeprip_script)
    ]
    
    passed = 0
    total = len(essential_tests)
    
    for test_name, test_func in essential_tests:
        try:
            result = test_func()
            if result:
                passed += 1
            print()
        except Exception as e:
            tester.print_status(f"Test '{test_name}' failed: {str(e)}", "error")
    
    print(f"{Fore.CYAN}Quick Test Results: {passed}/{total} passed{Style.RESET_ALL}")
    
    if passed >= 4:  # Allow 1 failure in quick tests
        print(f"{Fore.GREEN}✅ DeepRip appears ready for basic operations{Style.RESET_ALL}")
        return True
    else:
        print(f"{Fore.RED}❌ DeepRip has critical issues{Style.RESET_ALL}")
        print("Run full tests with: python3 test_system.py")
        return False


if __name__ == "__main__":
    main()