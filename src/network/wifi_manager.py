

import os
import platform
import subprocess
import time
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET

from src.config.settings import (
    WIFI_SSID,
    WIFI_SECURITY,
    WIFI_EAP_METHOD,
    WIFI_PHASE2_AUTH,
    WIFI_CONNECT_TIMEOUT,
    WINDOWS_SETTINGS,
    PASSWORD_PREFIX,
    EXPECTED_PASSWORD_LENGTH,
)
from src.config.translations import translator, t
from src.utils.system_utils import (
    get_os_type,
    is_admin,
    run_cmd,
    system_info,
)


if get_os_type() == "Windows":
    try:
        from src.utils.windows_eap_credentials import (
            store_windows_eap_credentials,
            clear_windows_eap_credentials,
            check_windows_eap_credentials,
        )
    except ImportError:
        store_windows_eap_credentials = None
        clear_windows_eap_credentials = None
        check_windows_eap_credentials = None
else:

    store_windows_eap_credentials = None
    clear_windows_eap_credentials = None
    check_windows_eap_credentials = None


class WiFiConnectionError(Exception):
    pass


class WiFiCredentials:
    def __init__(self, student_id, birthday=""):
        self.student_id = student_id.strip()
        self.birthday = ""  # stored as ddmmyyyy (8 digits) when set
        if birthday:
            # Accept a variety of birthday/password formats and normalize
            self.set_birthday(birthday.strip())

        self._validate_credentials()

    def _validate_credentials(self):
        if not self.student_id:
            raise ValueError(t("student_id_empty"))


        if not self.student_id.replace("-", "").replace("/", "").isdigit():
            pass

    def get_username(self):
        return self.student_id

    def get_password(self, birthday_ddmmyy=None):

        if birthday_ddmmyy:
            normalized = self._normalize_birthday_input(birthday_ddmmyy.strip())
            return f"{PASSWORD_PREFIX}{normalized}"


        if self.birthday:
            return f"{PASSWORD_PREFIX}{self.birthday}"


        return PASSWORD_PREFIX

    def set_birthday(self, birthday_ddmmyy):

        if not birthday_ddmmyy or not isinstance(birthday_ddmmyy, str):
            raise ValueError("Birthday must be a non-empty string")

        val = birthday_ddmmyy.strip()


        if val.startswith(PASSWORD_PREFIX):
            remainder = val[len(PASSWORD_PREFIX) :]
            val = remainder


        if val.isdigit() and len(val) == 8:

            day = int(val[:2])
            month = int(val[2:4])
            if not (1 <= day <= 31 and 1 <= month <= 12):
                raise ValueError("Invalid date in birthday")

            self.birthday = val
            return

        if val.isdigit() and len(val) == 6:

            day = int(val[:2])
            month = int(val[2:4])
            if not (1 <= day <= 31 and 1 <= month <= 12):
                raise ValueError("Invalid date in birthday")

            yy = val[4:6]
            expanded = f"{val[:4]}20{yy}"
            self.birthday = expanded
            return

        raise ValueError(t("birthday_invalid"))

    @staticmethod
    def _normalize_birthday_input(raw):
        if not raw:
            raise ValueError("Empty birthday input")

        s = raw.strip()


        if s.startswith(PASSWORD_PREFIX):
            remainder = s[len(PASSWORD_PREFIX) :]
            if remainder.isdigit() and len(remainder) == 8:
                return remainder
            if remainder.isdigit() and len(remainder) == 6:
                return f"{remainder[:4]}20{remainder[4:]}"
            raise ValueError("Invalid password format after prefix")


        if s.isdigit() and len(s) == 8:
            return s


        if s.isdigit() and len(s) == 6:
            return f"{s[:4]}20{s[4:]}"

        raise ValueError(t("birthday_invalid"))


class WindowsWiFiManager:
    @staticmethod
    def create_wpa2_enterprise_profile(credentials):

        auth = "WPA2"
        if isinstance(WIFI_SECURITY, str):
            sec = WIFI_SECURITY.lower()
            if "wpa2" in sec:
                auth = "WPA2"
            elif "wpa" in sec:
                auth = "WPA"

        eap_method = (WIFI_EAP_METHOD or "PEAP").strip().upper()
        phase2 = (WIFI_PHASE2_AUTH or "MSCHAPv2").strip().upper()


        eap_type_outer = 25
        eap_type_inner = 26


        profile_xml = f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{WIFI_SSID}</name>
    <SSIDConfig>
        <SSID>
            <name>{WIFI_SSID}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>{auth}</authentication>
                <encryption>AES</encryption>
                <useOneX>true</useOneX>
            </authEncryption>
            <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
                <cacheUserData>true</cacheUserData>
                <authMode>user</authMode>
                <singleSignOn>
                    <type>preLogon</type>
                    <maxDelay>10</maxDelay>
                    <allowAdditionalDialogs>false</allowAdditionalDialogs>
                    <userBasedVirtualLan>false</userBasedVirtualLan>
                </singleSignOn>
                <EAPConfig>
                    <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                        <EapMethod>
                            <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">{eap_type_outer}</Type>
                            <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
                            <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
                            <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId>
                        </EapMethod>
                        <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
                            <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                                <Type>{eap_type_outer}</Type>
                                <EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1">
                                    <ServerValidation>
                                        <DisableUserPromptForServerValidation>true</DisableUserPromptForServerValidation>
                                        <ServerNames></ServerNames>
                                        <TrustedRootCA></TrustedRootCA>
                                    </ServerValidation>
                                    <FastReconnect>true</FastReconnect>
                                    <InnerEapOptional>false</InnerEapOptional>
                                    <Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1">
                                        <Type>{eap_type_inner}</Type>
                                        <EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1">
                                            <UseWinLogonCredentials>false</UseWinLogonCredentials>
                                        </EapType>
                                    </Eap>
                                    <EnableQuarantineChecks>false</EnableQuarantineChecks>
                                    <RequireCryptoBinding>false</RequireCryptoBinding>
                                    <PeapExtensions>
                                        <PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</PerformServerValidation>
                                        <AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</AcceptServerName>
                                    </PeapExtensions>
                                </EapType>
                            </Eap>
                        </Config>
                    </EapHostConfig>
                </EAPConfig>
            </OneX>
        </security>
    </MSM>
</WLANProfile>"""
        return profile_xml

    @staticmethod
    def add_wifi_profile(credentials):
        try:
            profile_xml = WindowsWiFiManager.create_wpa2_enterprise_profile(credentials)

            temp_file = (
                Path(tempfile.gettempdir()) / WINDOWS_SETTINGS["temp_profile_name"]
            )

            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(profile_xml)

            success, stdout, stderr = run_cmd(
                [
                    "netsh",
                    "wlan",
                    "add",
                    "profile",
                    f"filename={temp_file}",
                    "user=current",
                ],
                timeout=WINDOWS_SETTINGS["netsh_timeout"],
            )

            temp_file.unlink(missing_ok=True)

            if success:
                return True, t("profile_added", ssid=WIFI_SSID)
            else:
                return False, f"Failed to add WiFi profile: {stderr}"

        except Exception as e:
            return False, f"Profile creation error: {e}"

    @staticmethod
    def _connect_wifi_simple(credentials, password):
        try:
            profile_success, profile_msg = WindowsWiFiManager.add_wifi_profile(credentials)
            if not profile_success:
                return False, f"Couldn't set up WiFi profile: {profile_msg}"


            try:
                run_cmd(["netsh", "wlan", "disconnect"], timeout=5)
                time.sleep(1)
            except Exception:
                pass

            connect_cmd = ["netsh", "wlan", "connect", f"ssid={WIFI_SSID}", f"name={WIFI_SSID}"]

            success, stdout, stderr = run_cmd(connect_cmd, timeout=WIFI_CONNECT_TIMEOUT)

            if success:

                try:
                    import threading
                    def show_credential_prompt():
                        import tkinter.messagebox as msgbox
                        time.sleep(2)
                        msgbox.showinfo(
                            "Enter Credentials",
                            f"Windows will prompt for credentials.\n\n"
                            f"Username: {credentials.student_id}\n"
                            f"Password: {password}\n\n"
                            f"Enter these when prompted."
                        )
                    
                    thread = threading.Thread(target=show_credential_prompt, daemon=True)
                    thread.start()
                except Exception:
                    pass


                for i in range(15):
                    time.sleep(2)
                    if WindowsWiFiManager.is_connected_to_network():
                        return True, "Connected successfully!"
                
                return (False, "Connection started. Please enter your credentials when Windows prompts you.")
            else:
                return False, f"Connection failed: {stderr}"

        except Exception as e:
            return False, f"Connection error: {e}"

    @staticmethod
    def _connect_wifi_legacy(
        credentials: WiFiCredentials, password
    ):
        
        try:
            # Delete any old profiles first to start fresh
            # Old profiles might have stale credentials or wrong settings. Starting clean
            # avoids weird "it worked yesterday but not today" issues.
            try:
                delete_cmd = ["netsh", "wlan", "delete", "profile", f"name={WIFI_SSID}"]
                if is_admin():
                    delete_cmd.append("user=all")  # Remove for all users if we can
                else:
                    delete_cmd.append("user=current")
                run_cmd(delete_cmd, timeout=10)
            except Exception:
                pass  # Profile might not exist yet, that's fine

            profile_success, profile_msg = WindowsWiFiManager.add_wifi_profile(
                credentials
            )
            if not profile_success:
                return False, t("profile_setup_failed", message=profile_msg)

            # Set these profile parameters before storing credentials.
            # If you change them afterwards, Windows sometimes wipes the stored credentials.
            # This is a Windows quirk - it treats profile changes as "new" profiles and
            # clears the credential cache. So we configure everything first, then store creds.
            try:
                # Set to user auth mode
                run_cmd([
                    "netsh", "wlan", "set", "profileparameter",
                    f"name={WIFI_SSID}", "authMode=userOnly"
                ], timeout=10)
                
                # Enable auto-connect
                run_cmd([
                    "netsh", "wlan", "set", "profileparameter",
                    f"name={WIFI_SSID}", "connectionMode=auto"
                ], timeout=10)
                
                # Set connection type
                run_cmd([
                    "netsh", "wlan", "set", "profileparameter",
                    f"name={WIFI_SSID}", "connectionType=ESS"
                ], timeout=10)
            except Exception:
                pass

            # Try to store the credentials in Windows credential manager.
            # On Windows 11 22H2+ with Credential Guard enabled, this usually fails
            # silently due to security restrictions. Not much we can do about that.
            # Credential Guard is a Windows security feature that isolates secrets in
            # a virtualized container - great for security, annoying for auto-login.
            cred_stored = False
            credential_guard_active = WindowsWiFiManager.is_credential_guard_enabled()
            
            if store_windows_eap_credentials and not credential_guard_active:
                try:
                    cred_success, cred_msg = store_windows_eap_credentials(
                        WIFI_SSID, credentials.student_id, password
                    )
                    cred_stored = bool(cred_success)
                    
                    # Double-check the credentials actually stuck
                    # Sometimes Windows says "OK" but doesn't actually persist them.
                    if cred_stored and check_windows_eap_credentials:
                        time.sleep(0.5)  # Windows needs a moment to write to credential store
                        present, msg = check_windows_eap_credentials(WIFI_SSID)
                        cred_stored = bool(present)
                except Exception:
                    cred_stored = False

            # Disconnect first to start fresh
            try:
                run_cmd(["netsh", "wlan", "disconnect"], timeout=5)
                time.sleep(1)
            except Exception:
                pass  # Already disconnected, that's fine

            # Connect to the WiFi network
            connect_cmd = [
                "netsh",
                "wlan",
                "connect",
                f"ssid={WIFI_SSID}",
                f"name={WIFI_SSID}",
            ]

            success, stdout, stderr = run_cmd(connect_cmd, timeout=WIFI_CONNECT_TIMEOUT)
            
            # If we couldn't store credentials, show a popup to guide the user
            if not cred_stored or credential_guard_active:
                try:
                    import threading
                    def show_credential_prompt():
                        import tkinter.messagebox as msgbox
                        time.sleep(2)
                        msgbox.showinfo(
                            t("credentials_required"),
                            t("windows_prompt_message", username=credentials.student_id)
                        )
                    
                    thread = threading.Thread(target=show_credential_prompt, daemon=True)
                    thread.start()
                except Exception:
                    pass

            if success:
                # Wait for EAP authentication to complete
                max_wait_seconds = 30 if cred_stored else 15
                for attempt in range(max_wait_seconds // 2):
                    time.sleep(2)
                    if WindowsWiFiManager.is_connected_to_network():
                        return True, t("connection_success")
                
                # Timed out waiting for connection
                if not cred_stored or credential_guard_active:
                    msg = t("action_needed_message", ssid=WIFI_SSID)
                    if credential_guard_active:
                        msg += "\n\nNote: Windows Credential Guard is active. You'll need to enter credentials each time you connect. This is a Windows security feature."
                    else:
                        msg += " Credentials could not be stored automatically. Please enter them manually in Windows."
                    return (False, msg)
                else:
                    return (False, t("connection_pending") + " Authentication may still be in progress.")
            else:
                return False, t("connection_failed") + f": {stderr}"

        except Exception as e:
            return False, t("connection_error", error=str(e))

    @staticmethod
    def connect_to_wifi(
        credentials: WiFiCredentials, password
    ):
        
        from src.utils.system_utils import should_use_native_wifi_connection
        
        try:
            # Check if we should use the simple modern method
            if should_use_native_wifi_connection():
                print(f"[WiFi] trying simple method (win11 stuff)")
                return WindowsWiFiManager._connect_wifi_simple(credentials, password)
            else:
                print(f"[WiFi] using old method (legacy windows)")
                return WindowsWiFiManager._connect_wifi_legacy(credentials, password)
        
        except Exception as e:
            return False, f"WiFi connection error: {e}"

    @staticmethod
    def is_credential_guard_enabled():
        
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
            )
            try:
                winreg.QueryValueEx(key, "IsolatedCredentialsRootSecret")
                winreg.CloseKey(key)
                return True
            except FileNotFoundError:
                winreg.CloseKey(key)
                return False
        except Exception:
            return False

    @staticmethod
    def disconnect_wifi():
        
        try:
            success, stdout, stderr = run_cmd(
                ["netsh", "wlan", "disconnect"], timeout=10
            )

            if success:
                return True, t("disconnected")
            else:
                return False, t("connection_failed") + f": {stderr}"

        except Exception as e:
            return False, f"Disconnect error: {e}"

    @staticmethod
    def remove_wifi_profile():
        
        try:
            # clear eap creds first
            if clear_windows_eap_credentials:
                # windows keeps eap secrets sometimes even after deleting profile
                # so clear them manually to avoid weird auto-login stuff
                clear_windows_eap_credentials(WIFI_SSID)
            
            # only remove uneswa profile, dont touch other wifi
            delete_cmd = ["netsh", "wlan", "delete", "profile", f"name={WIFI_SSID}"]
            if is_admin():
                delete_cmd.append("user=all")
            else:
                delete_cmd.append("user=current")
            success, stdout, stderr = run_cmd(delete_cmd, timeout=10)

            if success:
                return True, t("profile_removed", ssid=WIFI_SSID)
            else:
                # some windows versions put errors in stdout instead of stderr
                combined = f"{stdout}\n{stderr}".lower()
                if ("not found" in combined) or ("cannot find" in combined) or ("no profiles" in combined):
                    return (
                        True,
                        t("profile_not_found", ssid=WIFI_SSID),
                    )
                # try different user scope if first one didnt work
                try:
                    alt_cmd = delete_cmd[:-1] + (["user=current"] if "user=all" in delete_cmd[-1] else ["user=all"])
                    alt_success, alt_out, alt_err = run_cmd(alt_cmd, timeout=10)
                    if alt_success:
                        return True, t("profile_removed", ssid=WIFI_SSID)
                    combined2 = f"{alt_out}\n{alt_err}".lower()
                    if ("not found" in combined2) or ("cannot find" in combined2) or ("no profiles" in combined2):
                        return (
                            True,
                            t("profile_not_found", ssid=WIFI_SSID),
                        )
                except Exception:
                    pass
                return False, f"Failed to remove UNESWA profile '{WIFI_SSID}': {stderr or stdout}"

        except Exception as e:
            return False, f"UNESWA profile removal error: {e}"

    @staticmethod
    def is_connected_to_network():
        
        try:
            success, stdout, stderr = run_cmd(
                ["netsh", "wlan", "show", "interfaces"], timeout=10
            )

            if success:
                lines = stdout.lower().split("\n")
                connected = any(
                    "state" in line and "connected" in line for line in lines
                )
                uneswa_network = any(WIFI_SSID.lower() in line for line in lines)

                return connected and uneswa_network

            return False

        except Exception:
            return False

    @staticmethod
    def get_wifi_status():
        
        try:
            success, stdout, stderr = run_cmd(
                ["netsh", "wlan", "show", "interfaces"], timeout=10
            )

            if not success:
                return {"status": "error", "message": stderr}

            status = {"status": "disconnected"}
            current_ssid = None
            state = None

            for line in stdout.split("\n"):
                line = line.strip()
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()

                    if "ssid" in key and not "bssid" in key:
                        current_ssid = value
                    elif "state" in key:
                        state = value.lower()

            if state and "connected" in state:
                if current_ssid and WIFI_SSID.lower() in current_ssid.lower():
                    status = {
                        "status": "connected",
                        "ssid": current_ssid,
                        "network_type": "UNESWA",
                    }
                else:
                    status = {
                        "status": "connected_other",
                        "ssid": current_ssid or "Unknown",
                        "network_type": "Other",
                    }

            return status

        except Exception as e:
            return {"status": "error", "message": str(e)}


class LinuxWiFiManager:
    

    @staticmethod
    def connect_to_wifi(
        credentials: WiFiCredentials, password
    ):
        
        try:
            # delete old connection first, might have bad creds
            LinuxWiFiManager._remove_existing_connection(WIFI_SSID)
            
            # simple connection - networkmanager handles the rest
            # device wifi connect is smarter than connection add
            cmd = [
                "nmcli",
                "device",
                "wifi",
                "connect",
                WIFI_SSID,
                "password",
                password,
            ]
            
            # networkmanager needs username for wpa2-enterprise
            # using connection add approach but simplified
            
            cmd = [
                "nmcli",
                "connection",
                "add",
                "type",
                "wifi",
                "con-name",
                WIFI_SSID,
                "ssid",
                WIFI_SSID,
                "wifi-sec.key-mgmt",
                "wpa-eap",
                "802-1x.identity",
                credentials.get_username(),
                "802-1x.anonymous-identity",
                credentials.get_username(),
                "802-1x.password",
                password,
                "802-1x.eap",
                "ttls",
                "802-1x.phase2-auth",
                "mschapv2",
                "802-1x.system-ca-certs",
                "no",
                "802-1x.password-flags",
                "0",
                "connection.autoconnect",
                "yes",
            ]

            success, stdout, stderr = run_cmd(cmd, timeout=WIFI_CONNECT_TIMEOUT)

            if success:
                # connection created, now activate
                activate_cmd = ["nmcli", "connection", "up", WIFI_SSID]
                activate_success, activate_stdout, activate_stderr = run_cmd(
                    activate_cmd, timeout=WIFI_CONNECT_TIMEOUT
                )
                
                if activate_success:
                    # wait a bit for connection
                    time.sleep(3)
                    if LinuxWiFiManager.is_connected_to_network():
                        return True, "Connected successfully!"
                    else:
                        return (False, "Connection created but authentication failed - check your credentials")
                else:
                    if "authentication" in activate_stderr.lower():
                        return False, "Authentication failed - double-check your student ID and birthday"
                    else:
                        return False, f"Couldn't activate connection: {activate_stderr}"
            else:
                # connection creation failed
                if "already exists" in stderr.lower():
                    # connection exists already, just activate
                    activate_cmd = ["nmcli", "connection", "up", WIFI_SSID]
                    activate_success, activate_stdout, activate_stderr = run_cmd(
                        activate_cmd, timeout=WIFI_CONNECT_TIMEOUT
                    )
                    if activate_success:
                        return True, "Connected successfully!"
                    else:
                        # existing connection broken, delete and retry
                        LinuxWiFiManager._remove_existing_connection(WIFI_SSID)
                        return LinuxWiFiManager.connect_to_wifi(credentials, password)
                else:
                    return False, f"Connection failed: {stderr}"

        except Exception as e:
            return False, f"WiFi connection error: {e}"
    
    @staticmethod
    def _remove_existing_connection(connection_name):
        
        try:
            run_cmd(["nmcli", "connection", "delete", connection_name], timeout=10)
        except Exception:
            pass  # connection doesnt exist, thats ok

    @staticmethod
    def disconnect_wifi():
        
        try:
            success, stdout, stderr = run_cmd(
                ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active"],
                timeout=10,
            )

            wifi_connections = []
            if success:
                for line in stdout.split("\n"):
                    if line and "wifi" in line.lower():
                        conn_name = line.split(":")[0]
                        wifi_connections.append(conn_name)

            results = []
            for conn_name in wifi_connections:
                success, stdout, stderr = run_cmd(
                    ["nmcli", "connection", "down", conn_name], timeout=10
                )

                if success:
                    results.append(f"Disconnected from {conn_name}")
                else:
                    results.append(f"Failed to disconnect {conn_name}: {stderr}")

            if results:
                return True, "; ".join(results)
            else:
                return True, "No active WiFi connections to disconnect"

        except Exception as e:
            return False, f"Disconnect error: {e}"

    @staticmethod
    def remove_wifi_profile():
        
        try:
            success, stdout, stderr = run_cmd(
                ["nmcli", "-t", "-f", "NAME", "connection", "show"], timeout=10
            )

            if not success:
                return False, f"Failed to list connections: {stderr}"

            uneswa_connections = []
            for line in stdout.split("\n"):
                line = line.strip()
                if line:
                    if (
                        WIFI_SSID.lower() in line.lower()
                        or line.lower() == WIFI_SSID.lower()
                        or line.lower().startswith(WIFI_SSID.lower())
                    ):
                        uneswa_connections.append(line)

            if not uneswa_connections:
                return True, f"No UNESWA WiFi profiles found (SSID: '{WIFI_SSID}')"

            results = []
            removed_count = 0

            for conn_name in uneswa_connections:
                if WIFI_SSID.lower() not in conn_name.lower():
                    results.append(f"Skipped non-UNESWA profile: {conn_name}")
                    continue

                # remove connection (removes stored creds too)
                success, stdout, stderr = run_cmd(
                    ["nmcli", "connection", "delete", conn_name], timeout=10
                )

                if success:
                    results.append(f"Removed UNESWA profile and credentials: {conn_name}")
                    removed_count += 1
                else:
                    results.append(
                        f"Failed to remove UNESWA profile {conn_name}: {stderr}"
                    )

            summary = f"Processed {len(uneswa_connections)} UNESWA profile(s), removed {removed_count}"
            full_message = f"{summary}. Details: " + "; ".join(results)

            return True, full_message

        except Exception as e:
            return False, f"UNESWA profile removal error: {e}"

    @staticmethod
    def is_connected_to_network():
        
        try:
            success, stdout, stderr = run_cmd(
                [
                    "nmcli",
                    "-t",
                    "-f",
                    "NAME,TYPE,DEVICE",
                    "connection",
                    "show",
                    "--active",
                ],
                timeout=10,
            )

            if success:
                for line in stdout.split("\n"):
                    if (
                        line
                        and "wifi" in line.lower()
                        and WIFI_SSID.lower() in line.lower()
                    ):
                        return True

            return False

        except Exception:
            return False

    @staticmethod
    def get_wifi_status():
        
        try:
            success, stdout, stderr = run_cmd(
                ["nmcli", "-t", "-f", "WIFI", "general", "status"], timeout=10
            )

            if not success:
                return {"status": "error", "message": "Failed to get WiFi status"}

            wifi_enabled = "enabled" in stdout.lower()
            if not wifi_enabled:
                return {"status": "disabled", "message": "WiFi is disabled"}

            success, stdout, stderr = run_cmd(
                [
                    "nmcli",
                    "-t",
                    "-f",
                    "NAME,TYPE,DEVICE",
                    "connection",
                    "show",
                    "--active",
                ],
                timeout=10,
            )

            if not success:
                return {"status": "disconnected", "message": "No active connections"}

            for line in stdout.split("\n"):
                if line and "wifi" in line.lower():
                    parts = line.split(":")
                    if len(parts) >= 1:
                        conn_name = parts[0]
                        if WIFI_SSID.lower() in conn_name.lower():
                            return {
                                "status": "connected",
                                "ssid": WIFI_SSID,
                                "connection_name": conn_name,
                                "network_type": "UNESWA",
                            }
                        else:
                            return {
                                "status": "connected_other",
                                "connection_name": conn_name,
                                "network_type": "Other",
                            }

            return {"status": "disconnected", "message": "Not connected to any WiFi"}

        except Exception as e:
            return {"status": "error", "message": str(e)}


class WiFiManager:
    

    def __init__(self):
        self.os_type = get_os_type()
        self.use_native_connection = system_info.should_use_native_wifi_connection()

        if self.os_type == "Windows":
            self.manager = WindowsWiFiManager()
        else:
            self.manager = LinuxWiFiManager()

    def connect(self, student_id, birthday_ddmmyy):
        
        try:
            credentials = WiFiCredentials(student_id, birthday_ddmmyy)
            password = credentials.get_password()

            if len(password) != len(PASSWORD_PREFIX) + 8:
                return (
                    False,
                    "Invalid password format - expected format: UneswaDDMMYYYY",
                )

            return self.manager.connect_to_wifi(credentials, password)

        except ValueError as e:
            return False, t("credential_error", error=str(e))
        except Exception as e:
            return False, t("connection_error", error=str(e))

    def disconnect(self):
        
        return self.manager.disconnect_wifi()

    def remove_profile(self):
        
        return self.manager.remove_wifi_profile()

    def is_connected(self):
        
        return self.manager.is_connected_to_network()

    def get_status(self):
        
        return self.manager.get_wifi_status()

    def is_network_available(self):
        
        try:
            if self.os_type == "Windows":
                success, stdout, stderr = run_cmd(
                    ["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=20
                )
                if success and WIFI_SSID.lower() in stdout.lower():
                    return True, f"Network '{WIFI_SSID}' is available"

            else:
                success, stdout, stderr = run_cmd(
                    ["nmcli", "dev", "wifi", "list", "--rescan", "yes"], timeout=20
                )

                if success and WIFI_SSID in stdout:
                    return True, f"Network '{WIFI_SSID}' is available"

            if success:
                return True, "Network scanning completed"
            else:
                return False, f"Network scan failed: {stderr}"

        except Exception as e:
            return False, f"Network availability check failed: {e}"


# Global WiFi manager instance
wifi_manager = WiFiManager()


# Convenience functions
def connect_to_university_wifi(
    student_id: str, birthday_ddmmyy
):
    
    return wifi_manager.connect(student_id, birthday_ddmmyy)


def disconnect_from_wifi():
    
    return wifi_manager.disconnect()


def is_connected_to_university_wifi():
    
    return wifi_manager.is_connected()


def get_wifi_connection_status():
    
    return wifi_manager.get_status()


def validate_wifi_credentials(
    student_id: str, birthday_ddmmyy
):
    
    try:
        credentials = WiFiCredentials(student_id, birthday_ddmmyy)
        password = credentials.get_password()

        if len(password) == EXPECTED_PASSWORD_LENGTH:
            return True, t("credentials_valid")
        else:
            return False, t("credentials_invalid")

    except Exception as e:
        return False, str(e)


