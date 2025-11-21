import ctypes
import ctypes.wintypes as wintypes

import platform


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]

class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", ctypes.c_wchar * 256),
        ("isState", wintypes.DWORD),
    ]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    # Variable-length array; we only access the first element.
    _fields_ = [
        ("dwNumberOfItems", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
    ]


class WindowsEAPCredentialManager:

    def __init__(self):
        # init these early in case __del__ gets called during setup
        # python can call __del__ at weird times
        self.client_handle = None
        self.negotiated_version = wintypes.DWORD()
        self._guid_storage = None
        
        if platform.system() != "Windows":
            raise RuntimeError("WindowsEAPCredentialManager only works on Windows")
        
        try:
            # wlanapi.dll is windows wifi library
            # built into windows, should always work unless wifi disabled
            self.wlanapi = ctypes.windll.LoadLibrary("wlanapi.dll")
        except Exception as e:
            raise RuntimeError(f"Failed to load wlanapi.dll: {e}")

        # setup function prototypes
        # need to tell ctypes what args each windows api function expects
        DWORD = wintypes.DWORD
        HANDLE = wintypes.HANDLE
        PVOID = ctypes.c_void_p

        self.wlanapi.WlanOpenHandle.argtypes = [DWORD, PVOID, ctypes.POINTER(DWORD), ctypes.POINTER(HANDLE)]
        self.wlanapi.WlanOpenHandle.restype = DWORD

        self.wlanapi.WlanCloseHandle.argtypes = [HANDLE, PVOID]
        self.wlanapi.WlanCloseHandle.restype = DWORD

        self.wlanapi.WlanEnumInterfaces.argtypes = [HANDLE, PVOID, ctypes.POINTER(PVOID)]
        self.wlanapi.WlanEnumInterfaces.restype = DWORD

        self.wlanapi.WlanFreeMemory.argtypes = [PVOID]
        self.wlanapi.WlanFreeMemory.restype = None

        self.wlanapi.WlanSetProfileEapXmlUserData.argtypes = [
            HANDLE,
            ctypes.POINTER(GUID),
            ctypes.c_wchar_p,
            DWORD,  # Reserved, must be 0 per docs
            ctypes.c_wchar_p,
            PVOID,
        ]
        self.wlanapi.WlanSetProfileEapXmlUserData.restype = DWORD

        self.wlanapi.WlanSetProfileEapUserData.argtypes = [
            HANDLE,
            ctypes.POINTER(GUID),
            ctypes.c_wchar_p,
            DWORD,
            DWORD,
            PVOID,
            PVOID,
        ]
        self.wlanapi.WlanSetProfileEapUserData.restype = DWORD

        # some windows builds dont have WlanGetProfileEapUserData
        # older versions or minimal installs might not have this
        self._has_get_eap = True
        try:
            getattr(self.wlanapi, "WlanGetProfileEapUserData")
            self.wlanapi.WlanGetProfileEapUserData.argtypes = [
                HANDLE,
                ctypes.POINTER(GUID),
                ctypes.c_wchar_p,
                DWORD,
                ctypes.POINTER(DWORD),
                ctypes.POINTER(PVOID),
                PVOID,
            ]
            self.wlanapi.WlanGetProfileEapUserData.restype = DWORD
        except AttributeError:
            self._has_get_eap = False

    def _open_handle(self):
        if self.client_handle:
            return True  # already open
        
        try:
            client_handle = wintypes.HANDLE()
            negotiated_version = wintypes.DWORD()
            
            # ask windows for wlan service access
            # version 2 = vista and later
            result = self.wlanapi.WlanOpenHandle(
                wintypes.DWORD(2),  # client version vista+
                None,  # Reserved
                ctypes.byref(negotiated_version),
                ctypes.byref(client_handle)
            )
            
            if result == 0:  # ERROR_SUCCESS
                self.client_handle = client_handle
                self.negotiated_version = negotiated_version
                return True
            return False
        except Exception:
            return False

    def _close_handle(self):
        if hasattr(self, 'client_handle') and self.client_handle:
            try:
                self.wlanapi.WlanCloseHandle(self.client_handle, None)
            except Exception:
                pass
            finally:
                self.client_handle = None

    def _get_interface_guid(self):
        if not self._open_handle():
            return None
        
        try:
            list_ptr = ctypes.c_void_p()

            result = self.wlanapi.WlanEnumInterfaces(
                self.client_handle,
                None,
                ctypes.byref(list_ptr),
            )

            if result != 0 or not list_ptr.value:
                return None

            try:
                interface_list = ctypes.cast(
                    list_ptr.value, ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)
                ).contents
                if interface_list.dwNumberOfItems > 0:
                    # list memory owned by wlanapi, becomes invalid after WlanFreeMemory
                    # keep our own copy of guid
                    self._guid_storage = GUID()
                    self._guid_storage.Data1 = interface_list.InterfaceInfo[0].InterfaceGuid.Data1
                    self._guid_storage.Data2 = interface_list.InterfaceInfo[0].InterfaceGuid.Data2
                    self._guid_storage.Data3 = interface_list.InterfaceInfo[0].InterfaceGuid.Data3
                    for i in range(8):
                        self._guid_storage.Data4[i] = interface_list.InterfaceInfo[0].InterfaceGuid.Data4[i]
                    return ctypes.byref(self._guid_storage)
                return None
            finally:
                self.wlanapi.WlanFreeMemory(ctypes.c_void_p(list_ptr.value))
        except Exception:
            return None

    def set_eap_credentials(self, profile_name, username, password, domain=""):
        if not self._open_handle():
            return False, "Failed to open WLAN handle"
        
        interface_guid = self._get_interface_guid()
        if not interface_guid:
            return False, "No wireless interface found"
        
        # build eap credentials xml
        # windows stores wifi creds in specific xml format
        # peap (type 25) with mschapv2 (type 26)
        eap_xml = f"""<?xml version="1.0"?>
<EapHostUserCredentials xmlns="http://www.microsoft.com/provisioning/EapHostUserCredentials" 
                        xmlns:eapCommon="http://www.microsoft.com/provisioning/EapCommon" 
                        xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapMethodUserCredentials">
    <EapMethod>
        <eapCommon:Type>25</eapCommon:Type>
        <eapCommon:AuthorId>0</eapCommon:AuthorId>
    </EapMethod>
    <Credentials xmlns:eapUser="http://www.microsoft.com/provisioning/EapUserPropertiesV1" 
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                 xmlns:baseEap="http://www.microsoft.com/provisioning/BaseEapUserPropertiesV1" 
                 xmlns:MsPeap="http://www.microsoft.com/provisioning/MsPeapUserPropertiesV1" 
                 xmlns:MsChapV2="http://www.microsoft.com/provisioning/MsChapV2UserPropertiesV1">
        <baseEap:Eap>
            <baseEap:Type>25</baseEap:Type>
            <MsPeap:EapType>
                <MsPeap:RoutingIdentity>{username}</MsPeap:RoutingIdentity>
                <baseEap:Eap>
                    <baseEap:Type>26</baseEap:Type>
                    <MsChapV2:EapType>
                        <MsChapV2:Username>{username}</MsChapV2:Username>
                        <MsChapV2:Password>{password}</MsChapV2:Password>
                        <MsChapV2:LogonDomain>{domain}</MsChapV2:LogonDomain>
                    </MsChapV2:EapType>
                </baseEap:Eap>
            </MsPeap:EapType>
        </baseEap:Eap>
    </Credentials>
</EapHostUserCredentials>"""
        
        try:
            # Store credentials for current user
            result = self.wlanapi.WlanSetProfileEapXmlUserData(
                self.client_handle,
                interface_guid,
                ctypes.c_wchar_p(profile_name),
                wintypes.DWORD(0),  # current user scope
                ctypes.c_wchar_p(eap_xml),
                None,  # Reserved
            )

            if result == 0:  # ERROR_SUCCESS
                # Give Windows a moment to write the credentials to disk
                # Closing the handle too fast can prevent persistence
                import time
                time.sleep(0.2)
                return True, "EAP credentials stored successfully"
            elif result == 1168:  # ERROR_NOT_FOUND
                return False, f"Profile '{profile_name}' not found"
            elif result == 1200:  # ERROR_BAD_PROFILE
                return False, "Invalid profile or EAP configuration"
            elif result == 1206:  # ERROR_INVALID_PROFILE
                # This usually means Single Sign-On (SSO) is enabled on the profile,
                # which prevents manual credential storage
                return False, "Profile does not support credential storage (SSO may be enabled)"
            else:
                # Unknown error code - return it so we can debug
                return False, f"Failed to store credentials (error code: {result})"
        
        except Exception as e:
            return False, f"Exception storing credentials: {e}"
        finally:
            # Brief delay before closing to help Windows finish writing
            import time
            time.sleep(0.1)
            self._close_handle()

    def has_eap_credentials(self, profile_name):
        
        if not self._open_handle():
            return False, "Failed to open WLAN handle"

        interface_guid = self._get_interface_guid()
        if not interface_guid:
            return False, "No wireless interface found"

        # Some older Windows versions don't have this API
        if not getattr(self, "_has_get_eap", False):
            self._close_handle()
            return False, "EAP credential query not supported on this Windows build"

        try:
            size = wintypes.DWORD(0)
            data_ptr = ctypes.c_void_p()

            result = self.wlanapi.WlanGetProfileEapUserData(
                self.client_handle,
                interface_guid,
                ctypes.c_wchar_p(profile_name),
                wintypes.DWORD(0),  # current user scope
                ctypes.byref(size),
                ctypes.byref(data_ptr),
                None,
            )

            if result == 0 and size.value > 0 and data_ptr.value:
                try:
                    return True, "EAP credentials present"
                finally:
                    self.wlanapi.WlanFreeMemory(ctypes.c_void_p(data_ptr.value))
            elif result == 1168:  # not found
                return False, "No EAP credentials stored"
            else:
                return False, f"Cannot read EAP credentials (code {result})"
        except Exception as e:
            return False, f"Exception reading EAP credentials: {e}"
        finally:
            self._close_handle()

    def clear_eap_credentials(self, profile_name):
        
        if not self._open_handle():
            return False, "Failed to open WLAN handle"
        
        interface_guid = self._get_interface_guid()
        if not interface_guid:
            return False, "No wireless interface found"
        
        try:
            # Pass NULL to clear the stored credentials
            result = self.wlanapi.WlanSetProfileEapUserData(
                self.client_handle,
                interface_guid,
                ctypes.c_wchar_p(profile_name),
                wintypes.DWORD(0),  # current user scope
                wintypes.DWORD(0),  # data size = 0
                None,  # pbEapUserData = NULL
                None,  # Reserved
            )

            if result == 0:  # ERROR_SUCCESS
                return True, "EAP credentials cleared successfully"
            elif result == 1168:  # ERROR_NOT_FOUND
                return True, "No credentials found (already cleared)"
            else:
                return False, f"Failed to clear credentials (error code: {result})"
        
        except Exception as e:
            return False, f"Exception clearing credentials: {e}"
        finally:
            self._close_handle()

    def __del__(self):
        
        self._close_handle()


# convenience functions
def store_windows_eap_credentials(profile_name, username, password):
    try:
        manager = WindowsEAPCredentialManager()
        return manager.set_eap_credentials(profile_name, username, password)
    except Exception as e:
        return False, f"Failed to store credentials: {e}"


def clear_windows_eap_credentials(profile_name):
    try:
        manager = WindowsEAPCredentialManager()
        return manager.clear_eap_credentials(profile_name)
    except Exception as e:
        return False, f"Failed to clear credentials: {e}"


def check_windows_eap_credentials(profile_name):
    try:
        manager = WindowsEAPCredentialManager()
        return manager.has_eap_credentials(profile_name)
    except Exception as e:
        return False, f"Failed to check credentials: {e}"


