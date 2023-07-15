##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5547-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163829);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2022-31607", "CVE-2022-31608", "CVE-2022-31615");
  script_xref(name:"USN", value:"5547-1");
  script_xref(name:"IAVA", value:"2022-A-0309");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : NVIDIA graphics drivers vulnerabilities (USN-5547-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5547-1 advisory.

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where a local user
    with basic capabilities can cause a null-pointer dereference, which may lead to denial of service.
    (CVE-2022-31615)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where a
    local user with basic capabilities can cause improper input validation, which may lead to denial of
    service, escalation of privileges, data tampering, and limited information disclosure. (CVE-2022-31607)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in an optional D-Bus configuration file,
    where a local user with basic capabilities can impact protected D-Bus endpoints, which may lead to code
    execution, denial of service, escalation of privileges, information disclosure, and data tampering.
    (CVE-2022-31608)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5547-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31608");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libcuda1-384");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-384");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-384-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-libopencl1-384");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-opencl-icd-384");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-515-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-460");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-460-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-465");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-470");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-470-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-495");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-510");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-510-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-515");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-515-server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('18.04' >< os_release || '20.04' >< os_release || '22.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libcuda1-384', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-384', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-384-dev', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-libopencl1-384', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-opencl-icd-384', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-390', 'pkgver': '390.154-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-440-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-450-server', 'pkgver': '450.203.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-460', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-460-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-465', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-470', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-470-server', 'pkgver': '470.141.03-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-495', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-510', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-510-server', 'pkgver': '510.85.02-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-515', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-515-server', 'pkgver': '515.65.01-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libcuda1-384', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-384', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-384-dev', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-libopencl1-384', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-opencl-icd-384', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-390', 'pkgver': '390.154-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-440-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-450-server', 'pkgver': '450.203.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-460', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-460-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-465', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-470', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-470-server', 'pkgver': '470.141.03-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-495', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-510', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-510-server', 'pkgver': '510.85.02-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-515', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-515-server', 'pkgver': '515.65.01-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'libcuda1-384', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-cfg1-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-common-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-compute-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-decode-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-encode-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-extra-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-fbc1-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-gl-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-ifr1-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-ifr1-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-ifr1-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-ifr1-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-ifr1-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-ifr1-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-ifr1-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libnvidia-ifr1-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-384', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-384-dev', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-compute-utils-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-dkms-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-driver-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-headless-no-dkms-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-common-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-kernel-source-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-libopencl1-384', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-opencl-icd-384', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'nvidia-utils-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-390', 'pkgver': '390.154-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-440-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-450-server', 'pkgver': '450.203.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-460', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-460-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-465', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-470', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-470-server', 'pkgver': '470.141.03-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-495', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-510', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-510-server', 'pkgver': '510.85.02-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-515', 'pkgver': '515.65.01-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'xserver-xorg-video-nvidia-515-server', 'pkgver': '515.65.01-0ubuntu0.22.04.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libcuda1-384 / libnvidia-cfg1-390 / libnvidia-cfg1-440-server / etc');
}
