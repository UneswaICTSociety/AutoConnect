import os
import sys
import platform
import subprocess
import ctypes
from pathlib import Path
# removed typing imports

if platform.system() == "Windows":
    import ctypes.wintypes


class SystemInfo:

    def __init__(self):
        self.os_type = platform.system()
        self.os_release = platform.release()
        self.os_version = platform.version()
        self.architecture = platform.architecture()[0]
        self.machine = platform.machine()
        self._distro_info = None
        self._windows_build = None

    def is_windows(self):
        return self.os_type == "Windows"

    def is_linux(self):
        return self.os_type == "Linux"

    def is_macos(self):
        return self.os_type == "Darwin"

    def get_linux_distro(self):
        if not self.is_linux() or self._distro_info:
            return self._distro_info  # Already cached or not Linux

        try:
            # /etc/os-release is standard way to identify linux distros
            if os.path.exists("/etc/os-release"):
                distro_info = {}
                with open("/etc/os-release", "r") as f:
                    for line in f:
                        if "=" in line:
                            key, value = line.strip().split("=", 1)
                            distro_info[key] = value.strip('"')

                self._distro_info = {
                    "id": distro_info.get("ID", "unknown").lower(),
                    "name": distro_info.get("NAME", "Unknown"),
                    "version": distro_info.get("VERSION_ID", ""),
                    "pretty_name": distro_info.get("PRETTY_NAME", "Unknown Linux"),
                }
                return self._distro_info

            # fallback for older distros without /etc/os-release
            # check distro-specific files
            distro_files = [
                ("/etc/debian_version", "debian"),
                ("/etc/redhat-release", "rhel"),
                ("/etc/fedora-release", "fedora"),
                ("/etc/arch-release", "arch"),
                ("/etc/manjaro-release", "manjaro"),
            ]

            for file_path, distro_id in distro_files:
                if os.path.exists(file_path):
                    with open(file_path, "r") as f:
                        content = f.read().strip()

                    self._distro_info = {
                        "id": distro_id,
                        "name": content,
                        "version": "",
                        "pretty_name": content,
                    }
                    return self._distro_info

        except Exception:
            pass

        self._distro_info = {
            "id": "unknown",
            "name": "Unknown Linux",
            "version": "",
            "pretty_name": "Unknown Linux Distribution",
        }
        return self._distro_info

    def get_distro_id(self):
        distro = self.get_linux_distro()
        return distro["id"] if distro else "unknown"

    def is_supported_distro(self):
        if not self.is_linux():
            return self.is_windows()  # Windows is supported

        supported_distros = [
            "ubuntu",
            "debian",
            "arch",
            "manjaro",
            "fedora",
            "centos",
            "rhel",
            "opensuse",
        ]
        return self.get_distro_id() in supported_distros

    def get_windows_build_number(self):
        # build numbers clarify windows versions
        # 22000+ = windows 11, 19041-19045 = win10 etc
        if not self.is_windows():
            return None
        
        if self._windows_build is not None:
            return self._windows_build  # Already cached
        
        try:
            # windows version string like "10.0.22000" - want third part
            version_str = platform.version()
            parts = version_str.split('.')
            if len(parts) >= 3:
                self._windows_build = int(parts[2])
                return self._windows_build
        except Exception:
            pass
        
        return None
    
    def is_windows_11_or_newer(self):
        # windows 11 changed wifi behavior, need to detect
        if not self.is_windows():
            return False
        
        build = self.get_windows_build_number()
        if build is None:
            return False
        
        # win11 started at build 22000
        return build >= 22000
    
    def should_use_native_wifi_connection(self):
        # check if modern enough windows for wpa2-enterprise without xml
        if not self.is_windows():
            return False
        
        build = self.get_windows_build_number()
        if build is None:
            # cant determine build, assume legacy method
            return False
        
        # import constant from config to avoid circular imports
        try:
            from src.config.settings import WINDOWS_11_NATIVE_WIFI_MIN_BUILD
            return build >= WINDOWS_11_NATIVE_WIFI_MIN_BUILD
        except ImportError:
            # fallback if config not available
            return build >= 22000

    def get_system_summary(self):
        if self.is_windows():
            summary = f"Windows {self.os_release} ({self.architecture})"
            build = self.get_windows_build_number()
            if build:
                summary += f" Build {build}"
            return summary
        elif self.is_linux():
            distro = self.get_linux_distro()
            return distro["pretty_name"] if distro else f"Linux ({self.architecture})"
        else:
            return f"{self.os_type} {self.os_release} ({self.architecture})"


class PrivilegeManager:

    @staticmethod
    def is_admin():
        try:
            if platform.system() == "Windows":
                # windows: check if in administrators group
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # linux/macos: check if uid is 0 (root)
                return os.geteuid() == 0
        except Exception:
            return False

    @staticmethod
    def can_modify_system():
        if PrivilegeManager.is_admin():
            return True

        if platform.system() == "Windows":
            try:
                import winreg

                test_key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    "Software",
                    0,
                    winreg.KEY_READ | winreg.KEY_WRITE,
                )
                winreg.CloseKey(test_key)
                return True
            except Exception:
                return False
        else:
            # linux: check if can write to user config files
            home = Path.home()
            return os.access(home, os.W_OK)

    @staticmethod
    def get_privilege_status():
        if PrivilegeManager.is_admin():
            return True, "Running with administrator privileges"

        if PrivilegeManager.can_modify_system():
            return True, "Can modify user-level network settings"

        return False, "Insufficient privileges for network configuration"


class ProcessManager:

    @staticmethod
    def run_command(cmd, timeout=30, shell=False):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=shell,
                check=False,  # dont raise exception on non-zero exit
            )

            success = result.returncode == 0
            return success, result.stdout.strip(), result.stderr.strip()

        except subprocess.TimeoutExpired:
            return False, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            return False, "", f"Command execution failed: {e}"

    @staticmethod
    def is_command_available(command):
        try:
            subprocess.run(
                ["which" if platform.system() != "Windows" else "where", command],
                capture_output=True,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    @staticmethod
    def get_available_network_tools():
        tools = {}

        if platform.system() == "Windows":
            tools["netsh"] = ProcessManager.is_command_available("netsh")
            tools["powershell"] = ProcessManager.is_command_available("powershell")
        else:
            tools["nmcli"] = ProcessManager.is_command_available("nmcli")
            tools["iwconfig"] = ProcessManager.is_command_available("iwconfig")
            tools["wpa_supplicant"] = ProcessManager.is_command_available(
                "wpa_supplicant"
            )
            tools["systemctl"] = ProcessManager.is_command_available("systemctl")

        return tools


class PathManager:

    @staticmethod
    def get_config_dir():
        if platform.system() == "Windows":
            return Path(os.environ.get("APPDATA", "")) / "UNESWAWiFi"
        else:
            return Path.home() / ".config" / "uneswa-wifi"

    @staticmethod
    def get_temp_dir():
        import tempfile

        temp_base = Path(tempfile.gettempdir())
        temp_dir = temp_base / "uneswa-wifi"
        temp_dir.mkdir(exist_ok=True)
        return temp_dir

    @staticmethod
    def ensure_directory(path):
        try:
            path.mkdir(parents=True, exist_ok=True)
            return True
        except Exception:
            return False

    @staticmethod
    def safe_write_file(path, content, backup=True):
        try:
            if backup and path.exists():
                backup_path = path.with_suffix(path.suffix + ".backup")
                path.rename(backup_path)

            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

            return True
        except Exception:
            return False


# global instances
system_info = SystemInfo()
privilege_manager = PrivilegeManager()
process_manager = ProcessManager()
path_manager = PathManager()


# convenience functions
def get_os_type():
    return system_info.os_type


def get_distro_id():
    return system_info.get_distro_id()


def is_admin():
    return privilege_manager.is_admin()


def can_configure_network():
    return privilege_manager.can_modify_system()


def run_cmd(cmd, timeout=30):
    return process_manager.run_command(cmd, timeout)


def request_admin_elevation():
    if platform.system() != "Windows":
        return True
    
    if is_admin():
        return True
    
    try:
        import ctypes
        import sys
        
        # re-run script with admin rights
        script = sys.argv[0]
        params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
        
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        
        # shellexecutew returns >32 if succeeded
        if ret > 32:
            # elevated process running, exit this one
            sys.exit(0)
        else:
            return False
    except Exception:
        return False


def should_use_native_wifi_connection():
    # figure out if we can use simple wifi method or complex one
    # simple = just connect and let os handle it
    # complex = create xml profiles with peap/mschapv2 
    
    os_type = get_os_type()
    
    # linux and mac always use native - network managers handle it
    if os_type == "Linux" or os_type == "Darwin":
        return True
    
    # windows needs version check
    if os_type == "Windows":
        return system_info.should_use_native_wifi_connection()
    
    # unknown os, try native and hope for best
    return True
