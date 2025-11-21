
import requests
from dataclasses import dataclass
from bs4 import BeautifulSoup

from src.config.settings import PASSWORD_PREFIX


class DeviceRegistrationError(Exception):
    pass


@dataclass
class RegistrationResult:
    success: bool
    message: str
    already_registered: bool = False
    details: dict = None
    response_data: str = None

    def __post_init__(self):
        if self.details is None:
            self.details = {}


class DeviceRegistrationManager:
    
    def __init__(self):
        pass

    def register_device(self, student_id, birthday_ddmmyy):
        try:
            pwd = birthday_ddmmyy
            if not pwd.startswith(PASSWORD_PREFIX):
                pwd = f"{PASSWORD_PREFIX}{birthday_ddmmyy}"


            urls = [
                "http://kwnetreg.uniswa.sz/cgi-bin/register.cgi",
                "http://netreg.uniswa.sz/cgi-bin/register.cgi",
            ]

            for url in urls:
                try:
                    print(f"[Registration] Trying {url.split('/')[2]}...")


                    data = {"user": student_id, "pass": pwd, "submit": "ACCEPT"}

                    r = requests.post(url, data=data, timeout=10)

                    if r.status_code in [200, 302]:

                        try:
                            soup = BeautifulSoup(r.text, 'html.parser')
                            # find the main message in the response
                            body_text = soup.get_text().lower()
                        except:
                            body_text = r.text.lower()


                        if "not required" in body_text or "not on a network that requires registration" in body_text:
                            return RegistrationResult(
                                success=True,
                                message="Device is already registered (or not on campus network)",
                                already_registered=True,
                                details={"url": url, "status_code": r.status_code},
                            )

                        if "already registered" in body_text:
                            return RegistrationResult(
                                success=True,
                                message="Device is already registered",
                                already_registered=True,
                                details={"url": url, "status_code": r.status_code},
                            )


                        if any(w in body_text for w in ["success", "registered"]):
                            return RegistrationResult(
                                success=True,
                                message="Device registered successfully. Please restart your device.",
                                already_registered=False,
                                details={"url": url, "status_code": r.status_code},
                            )


                        return RegistrationResult(
                            success=True,
                            message="Registration submitted. Please restart your device if you have connection issues.",
                            already_registered=False,
                            details={"url": url, "status_code": r.status_code},
                        )
                    else:
                        print(
                            f"[Registration] Got status {r.status_code}, trying next URL..."
                        )
                        continue

                except requests.exceptions.RequestException as e:
                    print(
                        f"[Registration] Network error: {str(e)[:50]}, trying next URL..."
                    )
                    continue

            return RegistrationResult(
                success=False,
                message="Could not reach registration portal. Check your WiFi connection.",
                already_registered=False,
                details={"attempted_urls": urls},
            )

        except Exception as e:
            return RegistrationResult(
                success=False,
                message=f"Registration error: {e}",
                already_registered=False,
                details={"error": str(e)},
            )

    def test_registration_portals(self):
        results = {}
        test_urls = [
            ("Kwaluseni", "http://kwnetreg.uniswa.sz"),
            ("Generic", "http://netreg.uniswa.sz"),
        ]

        for name, url in test_urls:
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    results[name] = (True, "Portal accessible")
                else:
                    results[name] = (False, f"Status {r.status_code}")
            except Exception as e:
                results[name] = (False, f"Connection failed: {str(e)[:30]}")

        return results

    def get_available_campuses(self):
        results = self.test_registration_portals()
        return [name for name, (ok, _) in results.items() if ok]



device_registry = DeviceRegistrationManager()



def register_device_on_network(student_id, birthday_ddmmyy, campus=None):
    return device_registry.register_device(student_id, birthday_ddmmyy)


def test_registration_connectivity():
    return device_registry.test_registration_portals()


def get_available_registration_campuses():
    return device_registry.get_available_campuses()


def detect_current_campus():
    available = device_registry.get_available_campuses()
    return available[0] if available else None

