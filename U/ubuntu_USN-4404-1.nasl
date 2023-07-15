#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4404-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(137848);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-5963", "CVE-2020-5967", "CVE-2020-5973");
  script_xref(name:"USN", value:"4404-1");
  script_xref(name:"IAVA", value:"2020-A-0290-S");

  script_name(english:"Ubuntu 18.04 LTS / 19.10 / 20.04 : NVIDIA graphics drivers vulnerabilities (USN-4404-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Thomas E. Carroll discovered that the NVIDIA Cuda grpahics driver did
not properly perform access control when performing IPC. An attacker
could use this to cause a denial of service or possibly execute
arbitrary code. (CVE-2020-5963) It was discovered that the UVM driver
in the NVIDIA graphics driver contained a race condition. A local
attacker could use this to cause a denial of service. (CVE-2020-5967)
It was discovered that the NVIDIA virtual GPU guest drivers contained
an unspecified vulnerability that could potentially lead to privileged
operation execution. An attacker could use this to cause a denial of
service. (CVE-2020-5973).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4404-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected xserver-xorg-video-nvidia-390 and / or
xserver-xorg-video-nvidia-440 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5963");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-video-nvidia-440");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(18\.04|19\.10|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 19.10 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"xserver-xorg-video-nvidia-390", pkgver:"390.138-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"xserver-xorg-video-nvidia-440", pkgver:"440.100-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"xserver-xorg-video-nvidia-390", pkgver:"390.138-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"xserver-xorg-video-nvidia-440", pkgver:"440.100-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"xserver-xorg-video-nvidia-390", pkgver:"390.138-0ubuntu0.20.04.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"xserver-xorg-video-nvidia-440", pkgver:"440.100-0ubuntu0.20.04.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xserver-xorg-video-nvidia-390 / xserver-xorg-video-nvidia-440");
}
