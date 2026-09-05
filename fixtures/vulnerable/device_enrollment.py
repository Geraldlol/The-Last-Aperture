# V-030 — embedded-iot-ot-security / device-identity-and-secure-onboarding / Medium / CWE-1392
# Inert detector fixture: a shared default credential and public serial number authorize owner binding.

password = "admin"
device_id = read_serial_number()
cloud.enroll(device_id, password=password, owner=request.owner)
