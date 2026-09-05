# C-050 — clean detector mirror for one-time device onboarding
# Enrollment binds an attested device key to an authenticated owner after user presence.

bootstrap = secure_element.consume_one_time_bootstrap()
enrollment = cloud.begin_enrollment(attested_device=bootstrap.device_key)
require_user_presence()
cloud.bind_owner(enrollment, authenticated_owner.id)
