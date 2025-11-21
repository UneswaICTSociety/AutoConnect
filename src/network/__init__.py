from src.network.wifi_manager import (
    WiFiManager,
    WiFiCredentials,
    WindowsWiFiManager,
    LinuxWiFiManager,
    WiFiConnectionError,
    wifi_manager,
    connect_to_university_wifi,
    disconnect_from_wifi,
    is_connected_to_university_wifi,
    get_wifi_connection_status,
    validate_wifi_credentials,
)

from src.network.proxy_manager import (
    ProxyManager,
    WindowsProxyManager,
    LinuxProxyManager,
    ProxyConfigError,
    proxy_manager,
    enable_university_proxy,
    disable_university_proxy,
    is_university_proxy_configured,
    get_proxy_config_status,
)

from src.network.device_registry import (
    DeviceRegistrationManager,
    RegistrationResult,
    DeviceRegistrationError,
    device_registry,
    register_device_on_network,
    test_registration_connectivity,
    get_available_registration_campuses,
    detect_current_campus,
)

__version__ = "1.0.0"
__author__ = "ICT Society - University of Eswatini"
__description__ = "Network management for UNESWA WiFi AutoConnect"

# Expose main network management classes and functions
__all__ = [
    # WiFi Management
    "WiFiManager",
    "WiFiCredentials",
    "WindowsWiFiManager",
    "LinuxWiFiManager",
    "WiFiConnectionError",
    "wifi_manager",
    "connect_to_university_wifi",
    "disconnect_from_wifi",
    "is_connected_to_university_wifi",
    "get_wifi_connection_status",
    "validate_wifi_credentials",
    # Proxy Management
    "ProxyManager",
    "WindowsProxyManager",
    "LinuxProxyManager",
    "ProxyConfigError",
    "proxy_manager",
    "enable_university_proxy",
    "disable_university_proxy",
    "is_university_proxy_configured",
    "get_proxy_config_status",
    # Device Registration
    "DeviceRegistrationManager",
    "RegistrationResult",
    "DeviceRegistrationError",
    "device_registry",
    "register_device_on_network",
    "test_registration_connectivity",
    "get_available_registration_campuses",
    "detect_current_campus",
]


# Convenience class for complete network management
class NetworkManager:
    """
    Unified network management interface

    Provides a single interface for WiFi, proxy, and device registration operations.
    """

    def __init__(self):
        self.wifi = wifi_manager
        self.proxy = proxy_manager
        self.registry = device_registry

    def _ensure_proxy_enabled(self):
        # check proxy status and enable if needed
        is_configured = self.proxy.is_proxy_configured()
        
        if is_configured:
            return True, "Proxy already configured"
        
        return self.proxy.enable_proxy()

    def complete_setup(self, student_id, birthday_ddmmyy, campus=None):
        # does wifi, registration, and proxy in one go
        # wifi is critical, other stuff is nice to have
        
        results = {
            "wifi": {"success": False, "message": ""},
            "registration": {"success": False, "message": "", "already_registered": False},
            "proxy": {"success": False, "message": ""},
            "overall": {"success": False, "message": ""},
        }

        try:
            # wifi first - if this doesnt work nothing else will
            print("[Setup] Step 1/3: Connecting to WiFi...")
            wifi_ok, wifi_msg = self.wifi.connect(student_id, birthday_ddmmyy)
            results["wifi"] = {"success": wifi_ok, "message": wifi_msg}

            if not wifi_ok:
                results["overall"] = {
                    "success": False,
                    "message": f"Setup failed: Could not connect to WiFi. {wifi_msg}",
                }
                return results

            # register the device (not critical if it fails)
            print("[Setup] Step 2/3: Registering device...")
            reg = self.registry.register_device(student_id, birthday_ddmmyy)
            results["registration"] = {
                "success": reg.success,
                "message": reg.message,
                "already_registered": reg.already_registered,
            }

            # setup proxy
            print("[Setup] Step 3/3: Configuring proxy...")
            proxy_ok, proxy_msg = self._ensure_proxy_enabled()
            results["proxy"] = {"success": proxy_ok, "message": proxy_msg}

            # wifi is critical, other stuff is nice to have
            if wifi_ok:
                if reg.success and proxy_ok:
                    results["overall"] = {
                        "success": True,
                        "message": "Complete setup successful! You're connected to the university network.",
                    }
                elif reg.success or proxy_ok:
                    results["overall"] = {
                        "success": True,
                        "message": "WiFi connected. Some additional setup steps may need attention.",
                    }
                else:
                    results["overall"] = {
                        "success": True,
                        "message": "WiFi connected, but registration and proxy setup had issues. You may have limited internet access.",
                    }
            else:
                results["overall"] = {
                    "success": False,
                    "message": "Setup failed. Could not connect to WiFi.",
                }

            return results

        except Exception as e:
            results["overall"] = {"success": False, "message": f"Setup error: {e}"}
            return results

    def reset_all_settings(self):
        # reset all network settings
        results = {
            "wifi_disconnect": {"success": False, "message": ""},
            "wifi_profile_removal": {"success": False, "message": ""},
            "proxy_disable": {"success": False, "message": ""},
            "overall": {"success": False, "message": ""},
        }

        try:
            disconnect_success, disconnect_message = self.wifi.disconnect()
            results["wifi_disconnect"] = {
                "success": disconnect_success,
                "message": disconnect_message,
            }

            profile_success, profile_message = self.wifi.remove_profile()
            results["wifi_profile_removal"] = {
                "success": profile_success,
                "message": profile_message,
            }

            proxy_success, proxy_message = self.proxy.disable_proxy()
            results["proxy_disable"] = {
                "success": proxy_success,
                "message": proxy_message,
            }

            # Remove saved credentials
            try:
                from src.utils.credentials import remove_credentials
                remove_credentials()
            except Exception:
                pass

            # Overall success if most operations succeeded
            success_count = sum([disconnect_success, profile_success, proxy_success])

            if success_count >= 2:
                results["overall"] = {
                    "success": True,
                    "message": "UNESWA network settings reset successfully (other WiFi profiles preserved)",
                }
            else:
                results["overall"] = {
                    "success": False,
                    "message": "Some UNESWA settings may not have been reset properly",
                }

            return results

        except Exception as e:
            results["overall"] = {"success": False, "message": f"Reset error: {e}"}
            return results

    def get_connection_status(self):
        # get connection status
        return {
            "wifi": self.wifi.get_status(),
            "proxy": self.proxy.get_proxy_status(),
            "wifi_connected": self.wifi.is_connected(),
            "proxy_configured": self.proxy.is_proxy_configured(),
            "available_campuses": self.registry.get_available_campuses(),
        }


# Global network manager instance
network_manager = NetworkManager()

# Add to exports
__all__.append("NetworkManager")
__all__.append("network_manager")

