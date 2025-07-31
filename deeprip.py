#!/usr/bin/env python3
"""
DeepRip - Modern iOS App Extractor
Compatible with iOS up to 16.7.11 on jailbroken devices
Cross-platform Linux support
"""

import os
import sys
import time
import json
import tempfile
import zipfile
import shutil
import re
import argparse
import configparser
import signal
from pathlib import Path
from typing import Optional, Dict, List, Tuple

try:
    import frida
    import paramiko
    from scp import SCPClient
    import biplist
    from colorama import init, Fore, Style
    from tqdm import tqdm
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Please run the setup script first: ./setup_dependencies.sh")
    sys.exit(1)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class DeepRip:
    def __init__(self, config_path: str = None):
        """Initialize the iOS app extractor with configuration."""
        self.config = self._load_config(config_path)
        self.device = None
        self.ssh_client = None
        self.scp_client = None
        self.temp_dir = None
        self.frida_script = None
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _load_config(self, config_path: str = None) -> configparser.ConfigParser:
        """Load configuration from file."""
        config = configparser.ConfigParser()
        
        # Default configuration
        default_config = {
            'DEFAULT': {
                'ssh_host': '127.0.0.1',
                'ssh_port': '2222',
                'ssh_user': 'mobile',
                'ssh_pass': 'alpine',
                'output_dir': './dumps',
                'temp_dir': '/tmp/deeprip_dump',
                'frida_server_port': '27042',
                'max_retries': '3',
                'timeout': '30'
            }
        }
        
        for section, options in default_config.items():
            config.add_section(section) if section != 'DEFAULT' else None
            for key, value in options.items():
                config.set(section, key, value)
        
        # Load user configuration if exists
        config_file = config_path or os.path.expanduser('~/.deeprip_config')
        if os.path.exists(config_file):
            config.read(config_file)
            
        return config
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\n{Fore.YELLOW}Received signal {signum}. Cleaning up...")
        self.cleanup()
        sys.exit(0)
        
    def _print_status(self, message: str, level: str = "info"):
        """Print colored status messages."""
        colors = {
            "info": Fore.BLUE,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED
        }
        prefix = {
            "info": "[INFO]",
            "success": "[SUCCESS]",
            "warning": "[WARNING]",
            "error": "[ERROR]"
        }
        print(f"{colors.get(level, Fore.WHITE)}{prefix.get(level, '[INFO]')} {message}{Style.RESET_ALL}")
        
    def connect_device(self) -> bool:
        """Connect to iOS device via Frida."""
        try:
            # Try USB connection first
            self._print_status("Connecting to iOS device via USB...")
            device_manager = frida.get_device_manager()
            
            # Wait for device
            for _ in range(10):
                devices = device_manager.enumerate_devices()
                usb_devices = [d for d in devices if d.type == 'usb']
                
                if usb_devices:
                    self.device = usb_devices[0]
                    self._print_status(f"Connected to {self.device.name} ({self.device.id})", "success")
                    return True
                    
                time.sleep(1)
                
            # Try remote connection if USB fails
            self._print_status("USB connection failed, trying remote connection...")
            remote_device = frida.get_remote_device()
            self.device = remote_device
            self._print_status("Connected via remote connection", "success")
            return True
            
        except Exception as e:
            self._print_status(f"Failed to connect to device: {e}", "error")
            return False
            
    def setup_ssh_connection(self) -> bool:
        """Setup SSH connection to iOS device."""
        try:
            self._print_status("Setting up SSH connection...")
            
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect with retries
            max_retries = int(self.config.get('DEFAULT', 'max_retries'))
            for attempt in range(max_retries):
                try:
                    self.ssh_client.connect(
                        hostname=self.config.get('DEFAULT', 'ssh_host'),
                        port=int(self.config.get('DEFAULT', 'ssh_port')),
                        username=self.config.get('DEFAULT', 'ssh_user'),
                        password=self.config.get('DEFAULT', 'ssh_pass'),
                        timeout=int(self.config.get('DEFAULT', 'timeout'))
                    )
                    
                    self.scp_client = SCPClient(self.ssh_client.get_transport())
                    self._print_status("SSH connection established", "success")
                    return True
                    
                except Exception as e:
                    if attempt < max_retries - 1:
                        self._print_status(f"SSH connection attempt {attempt + 1} failed, retrying...", "warning")
                        time.sleep(2)
                    else:
                        raise e
                        
        except Exception as e:
            self._print_status(f"Failed to setup SSH connection: {e}", "error")
            self._print_status("Make sure iproxy is running: iproxy 2222 22", "warning")
            return False
            
    def list_applications(self) -> List[Dict]:
        """List installed applications on the device."""
        try:
            self._print_status("Enumerating applications...")
            applications = self.device.enumerate_applications()
            
            # Filter and sort applications
            apps = []
            for app in applications:
                apps.append({
                    'name': app.name,
                    'identifier': app.identifier,
                    'pid': app.pid,
                    'running': app.pid != 0
                })
                    
            apps.sort(key=lambda x: x['name'].lower())
            return apps
            
        except Exception as e:
            self._print_status(f"Failed to enumerate applications: {e}", "error")
            return []
            
    def find_application(self, app_identifier: str) -> Optional[Dict]:
        """Find application by name or bundle identifier."""
        applications = self.list_applications()
        
        # Try exact match first
        for app in applications:
            if (app['identifier'].lower() == app_identifier.lower() or 
                app['name'].lower() == app_identifier.lower()):
                return app
                
        # Try partial match
        matches = []
        for app in applications:
            if (app_identifier.lower() in app['identifier'].lower() or 
                app_identifier.lower() in app['name'].lower()):
                matches.append(app)
                
        if len(matches) == 1:
            return matches[0]
        elif len(matches) > 1:
            self._print_status(f"Multiple matches found for '{app_identifier}':", "warning")
            for i, app in enumerate(matches):
                print(f"  {i+1}. {app['name']} ({app['identifier']})")
            return None
        else:
            self._print_status(f"No application found matching '{app_identifier}'", "error")
            return None
            
    def spawn_application(self, bundle_id: str) -> int:
        """Spawn application and return PID."""
        try:
            self._print_status(f"Spawning application: {bundle_id}")
            pid = self.device.spawn([bundle_id])
            self.device.resume(pid)
            time.sleep(2)  # Wait for app to initialize
            self._print_status(f"Application spawned with PID: {pid}", "success")
            return pid
        except Exception as e:
            self._print_status(f"Failed to spawn application: {e}", "error")
            return 0
            
    def get_frida_script(self) -> str:
        """Get the Frida script for dumping."""
        return """
        // DeepRip iOS App Extraction Script
        // Compatible with iOS up to 16.7.11
        
        var modules_dict = {};
        var is_arm64 = Process.arch == 'arm64';
        
        function dump_module(module_name, module_base, module_size) {
            console.log("[+] Extracting module: " + module_name);
            
            var file_path = "/tmp/" + module_name + "_extracted";
            var file_handle = new File(file_path, "wb");
            
            if (file_handle) {
                try {
                    Memory.protect(ptr(module_base), module_size, 'r--');
                    var dump_buffer = Memory.readByteArray(ptr(module_base), module_size);
                    file_handle.write(dump_buffer);
                    file_handle.close();
                    console.log("[+] Module extracted to: " + file_path);
                    return file_path;
                } catch (e) {
                    console.log("[-] Error extracting module " + module_name + ": " + e);
                    if (file_handle) {
                        file_handle.close();
                    }
                    return null;
                }
            } else {
                console.log("[-] Failed to create extraction file for: " + module_name);
                return null;
            }
        }
        
        function get_app_modules() {
            var modules = Process.enumerateModules();
            var app_modules = [];
            var main_module = null;
            
            for (var i = 0; i < modules.length; i++) {
                var module = modules[i];
                
                // Skip system modules
                if (module.path.indexOf("/System/Library/") == 0 ||
                    module.path.indexOf("/usr/lib/") == 0 ||
                    module.path.indexOf("/usr/libexec/") == 0) {
                    continue;
                }
                
                app_modules.push({
                    name: module.name,
                    base: module.base,
                    size: module.size,
                    path: module.path
                });
                
                // Identify main executable
                if (module.path.indexOf(".app/") > 0 && !module.path.endsWith(".dylib") && 
                    !module.path.includes("/Frameworks/")) {
                    main_module = module;
                }
            }
            
            return {
                main: main_module,
                modules: app_modules
            };
        }
        
        function start_extraction() {
            console.log("[+] Starting application extraction...");
            
            var result = get_app_modules();
            var extracted_files = [];
            
            if (result.main) {
                console.log("[+] Main executable: " + result.main.name);
                var extract_path = dump_module(result.main.name, result.main.base, result.main.size);
                if (extract_path) {
                    extracted_files.push({
                        original_path: result.main.path,
                        extract_path: extract_path,
                        is_main: true
                    });
                }
            }
            
            // Extract frameworks and libraries
            for (var i = 0; i < result.modules.length; i++) {
                var module = result.modules[i];
                if (module.path != result.main.path) {
                    var extract_path = dump_module(module.name, module.base, module.size);
                    if (extract_path) {
                        extracted_files.push({
                            original_path: module.path,
                            extract_path: extract_path,
                            is_main: false
                        });
                    }
                }
            }
            
            send({
                type: "extraction_complete",
                files: extracted_files,
                app_info: {
                    name: result.main ? result.main.name : "unknown",
                    path: result.main ? result.main.path : "unknown"
                }
            });
        }
        
        // Start extraction when script loads
        setTimeout(start_extraction, 1000);
        """
        
    def extract_application(self, app_info: Dict) -> Optional[str]:
        """Extract the specified application."""
        try:
            bundle_id = app_info['identifier']
            app_name = app_info['name']
            
            self._print_status(f"Starting extraction process for: {app_name}")
            
            # Spawn application if not running
            pid = app_info['pid']
            if pid == 0:
                pid = self.spawn_application(bundle_id)
                if pid == 0:
                    return None
                    
            # Attach to process
            self._print_status(f"Attaching to process PID: {pid}")
            session = self.device.attach(pid)
            
            # Create and load script
            script_source = self.get_frida_script()
            script = session.create_script(script_source)
            
            # Set up message handler
            extraction_complete = False
            extraction_result = None
            
            def on_message(message, data):
                nonlocal extraction_complete, extraction_result
                if message['type'] == 'send':
                    if message['payload']['type'] == 'extraction_complete':
                        extraction_complete = True
                        extraction_result = message['payload']
                elif message['type'] == 'error':
                    self._print_status(f"Script error: {message['description']}", "error")
                    
            script.on('message', on_message)
            script.load()
            
            # Wait for extraction to complete
            self._print_status("Extracting application from memory...")
            timeout = int(self.config.get('DEFAULT', 'timeout'))
            
            for _ in range(timeout):
                if extraction_complete:
                    break
                time.sleep(1)
                
            if not extraction_complete:
                self._print_status("Extraction operation timed out", "error")
                return None
                
            # Download extracted files
            output_dir = self.config.get('DEFAULT', 'output_dir')
            os.makedirs(output_dir, exist_ok=True)
            
            app_extract_dir = os.path.join(output_dir, f"{app_name}_{int(time.time())}")
            os.makedirs(app_extract_dir, exist_ok=True)
            
            self._print_status("Downloading extracted files...")
            
            for file_info in extraction_result['files']:
                remote_path = file_info['extract_path']
                local_filename = os.path.basename(file_info['original_path'])
                local_path = os.path.join(app_extract_dir, local_filename)
                
                try:
                    self.scp_client.get(remote_path, local_path)
                    self._print_status(f"Downloaded: {local_filename}")
                    
                    # Clean up remote file
                    self.ssh_client.exec_command(f"rm -f {remote_path}")
                    
                except Exception as e:
                    self._print_status(f"Failed to download {local_filename}: {e}", "warning")
                    
            # Create IPA file
            ipa_path = self._create_ipa(app_extract_dir, app_name, extraction_result['app_info'])
            
            session.detach()
            return ipa_path
            
        except Exception as e:
            self._print_status(f"Failed to extract application: {e}", "error")
            return None
            
    def _create_ipa(self, extract_dir: str, app_name: str, app_info: Dict) -> str:
        """Create IPA file from extracted files."""
        try:
            self._print_status("Creating IPA file...")
            
            ipa_path = os.path.join(os.path.dirname(extract_dir), f"{app_name}_decrypted.ipa")
            
            with zipfile.ZipFile(ipa_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Add Payload directory structure
                payload_dir = f"Payload/{app_name}.app/"
                
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = payload_dir + os.path.relpath(file_path, extract_dir)
                        zipf.write(file_path, arcname)
                        
            self._print_status(f"IPA created: {ipa_path}", "success")
            return ipa_path
            
        except Exception as e:
            self._print_status(f"Failed to create IPA: {e}", "error")
            return extract_dir
            
    def cleanup(self):
        """Clean up resources."""
        if self.scp_client:
            self.scp_client.close()
        if self.ssh_client:
            self.ssh_client.close()
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
            
    def run(self, app_identifier: str, list_apps: bool = False):
        """Main execution method."""
        try:
            # Connect to device
            if not self.connect_device():
                return False
                
            # Setup SSH connection
            if not self.setup_ssh_connection():
                return False
                
            # List applications if requested
            if list_apps:
                apps = self.list_applications()
                print(f"\n{Fore.GREEN}Installed Applications:{Style.RESET_ALL}")
                print("-" * 80)
                print(f"{'Name':<30} {'Bundle ID':<35} {'Status':<10}")
                print("-" * 80)
                for app in apps:
                    status = f"Running (PID: {app['pid']})" if app['running'] else "Not Running"
                    color = Fore.GREEN if app['running'] else Fore.YELLOW
                    print(f"{app['name']:<30} {app['identifier']:<35} {color}{status}{Style.RESET_ALL}")
                return True
                
            # Find and extract application
            app_info = self.find_application(app_identifier)
            if not app_info:
                return False
                
            result = self.extract_application(app_info)
            if result:
                self._print_status(f"Extraction completed successfully: {result}", "success")
                return True
            else:
                return False
                
        except KeyboardInterrupt:
            self._print_status("Operation cancelled by user", "warning")
            return False
        except Exception as e:
            self._print_status(f"Unexpected error: {e}", "error")
            return False
        finally:
            self.cleanup()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="DeepRip - Modern iOS App Extractor - Compatible with iOS up to 16.7.11",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 deeprip.py -l                    # List all applications
  python3 deeprip.py "App Name"            # Extract by display name
  python3 deeprip.py com.example.app       # Extract by bundle identifier
  python3 deeprip.py -c custom_config.ini "App Name"  # Use custom config

Prerequisites:
  1. Jailbroken iOS device (up to iOS 16.7.11)
  2. Frida server installed on device (from Cydia/Sileo)
  3. SSH access enabled on device
  4. USB connection with iproxy running: iproxy 2222 22
        """)
    
    parser.add_argument(
        'app_identifier',
        nargs='?',
        help='Application name or bundle identifier to extract'
    )
    
    parser.add_argument(
        '-l', '--list',
        action='store_true',
        help='List all installed applications'
    )
    
    parser.add_argument(
        '-c', '--config',
        type=str,
        help='Path to custom configuration file'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output directory for extracted files'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.list and not args.app_identifier:
        parser.error("Either specify an app identifier or use --list to show applications")
    
    # Print banner
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                         DeepRip v1.0                         ║
║                   Modern iOS App Extractor                   ║
║                  Compatible with iOS ≤ 16.7.11               ║
║                    Cross-Platform Linux Support              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")
    
    # Create extractor instance
    extractor = DeepRip(config_path=args.config)
    
    # Override output directory if specified
    if args.output:
        extractor.config.set('DEFAULT', 'output_dir', args.output)
    
    # Run the extractor
    success = extractor.run(args.app_identifier, list_apps=args.list)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()