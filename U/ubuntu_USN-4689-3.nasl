##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4689-3. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145228);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-1052", "CVE-2021-1053");
  script_xref(name:"USN", value:"4689-3");
  script_xref(name:"IAVB", value:"2021-B-0005");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 : NVIDIA graphics drivers vulnerabilities (USN-4689-3)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4689-3 advisory.

  - NVIDIA GPU Display Driver for Windows and Linux, all versions, contains a vulnerability in the kernel mode
    layer (nvlddmkm.sys) handler for DxgkDdiEscape or IOCTL in which user-mode clients can access legacy
    privileged APIs, which may lead to denial of service, escalation of privileges, and information
    disclosure. (CVE-2021-1052)

  - NVIDIA GPU Display Driver for Windows and Linux, all versions, contains a vulnerability in the kernel mode
    layer (nvlddmkm.sys) handler for DxgkDdiEscape or IOCTL in which improper validation of a user pointer may
    lead to denial of service. (CVE-2021-1053)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4689-3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1052");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-cfg1-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-common-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-compute-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-decode-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-encode-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-extra-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-fbc1-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-gl-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libnvidia-ifr1-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-compute-utils-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-dkms-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-driver-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-headless-no-dkms-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-common-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-common-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-common-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-source-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-source-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-kernel-source-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nvidia-utils-450-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-418-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-440-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-450-server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-cfg1-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-common-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-compute-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-decode-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-encode-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-extra-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-fbc1-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-gl-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'libnvidia-ifr1-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-compute-utils-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-dkms-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-driver-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-headless-no-dkms-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-common-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-kernel-source-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'nvidia-utils-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-418-server', 'pkgver': '418.181.07-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-440-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '18.04', 'pkgname': 'xserver-xorg-video-nvidia-450-server', 'pkgver': '450.102.04-0ubuntu0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-cfg1-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-common-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-compute-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-decode-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-encode-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-extra-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-fbc1-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-gl-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libnvidia-ifr1-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-compute-utils-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-dkms-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-driver-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-headless-no-dkms-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-common-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-kernel-source-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'nvidia-utils-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-418-server', 'pkgver': '418.181.07-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-440-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'xserver-xorg-video-nvidia-450-server', 'pkgver': '450.102.04-0ubuntu0.20.04.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-cfg1-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-cfg1-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-cfg1-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-common-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-common-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-common-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-compute-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-compute-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-compute-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-decode-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-decode-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-decode-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-encode-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-encode-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-encode-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-extra-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-extra-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-fbc1-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-fbc1-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-fbc1-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-gl-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-gl-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-gl-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-ifr1-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-ifr1-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'libnvidia-ifr1-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-compute-utils-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-compute-utils-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-compute-utils-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-dkms-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-dkms-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-dkms-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-driver-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-driver-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-driver-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-headless-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-headless-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-headless-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-headless-no-dkms-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-headless-no-dkms-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-headless-no-dkms-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-kernel-common-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-kernel-common-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-kernel-common-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-kernel-source-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-kernel-source-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-kernel-source-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-utils-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-utils-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'nvidia-utils-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'xserver-xorg-video-nvidia-418-server', 'pkgver': '418.181.07-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'xserver-xorg-video-nvidia-440-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'},
    {'osver': '20.10', 'pkgname': 'xserver-xorg-video-nvidia-450-server', 'pkgver': '450.102.04-0ubuntu0.20.10.1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnvidia-cfg1-418-server / libnvidia-cfg1-440-server / etc');
}
