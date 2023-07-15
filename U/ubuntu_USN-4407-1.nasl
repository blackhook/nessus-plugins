#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4407-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138132);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-18922", "CVE-2019-15680", "CVE-2019-15681", "CVE-2019-15690", "CVE-2019-20788");
  script_xref(name:"USN", value:"4407-1");
  script_xref(name:"IAVA", value:"2020-A-0381");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.10 / 20.04 : LibVNCServer vulnerabilities (USN-4407-1)");
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
"It was discovered that LibVNCServer incorrectly handled decompressing
data. An attacker could possibly use this issue to cause LibVNCServer
to crash, resulting in a denial of service. (CVE-2019-15680) It was
discovered that an information disclosure vulnerability existed in
LibVNCServer when sending a ServerCutText message. An attacker could
possibly use this issue to expose sensitive information. This issue
only affected Ubuntu 19.10, Ubuntu 18.04 LTS, and Ubuntu 16.04 LTS.
(CVE-2019-15681) It was discovered that LibVNCServer incorrectly
handled cursor shape updates. If a user were tricked in to connecting
to a malicious server, an attacker could possibly use this issue to
cause LibVNCServer to crash, resulting in a denial of service, or
possibly execute arbitrary code. This issue only affected Ubuntu
19.10, Ubuntu 18.04 LTS, and Ubuntu 16.04 LTS. (CVE-2019-15690,
CVE-2019-20788) It was discovered that LibVNCServer incorrectly
handled decoding WebSocket frames. An attacker could possibly use this
issue to cause LibVNCServer to crash, resulting in a denial of
service, or possibly execute arbitrary code. This issue only affected
Ubuntu 19.10, Ubuntu 18.04 LTS, and Ubuntu 16.04 LTS. (CVE-2017-18922).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4407-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libvncclient1 and / or libvncserver1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20788");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvncclient1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libvncserver1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/06");
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
if (! preg(pattern:"^(16\.04|18\.04|19\.10|20\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 19.10 / 20.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"libvncclient1", pkgver:"0.9.10+dfsg-3ubuntu0.16.04.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libvncserver1", pkgver:"0.9.10+dfsg-3ubuntu0.16.04.4")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libvncclient1", pkgver:"0.9.11+dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libvncserver1", pkgver:"0.9.11+dfsg-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libvncclient1", pkgver:"0.9.11+dfsg-1.3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libvncserver1", pkgver:"0.9.11+dfsg-1.3ubuntu0.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"libvncclient1", pkgver:"0.9.12+dfsg-9ubuntu0.1")) flag++;
if (ubuntu_check(osver:"20.04", pkgname:"libvncserver1", pkgver:"0.9.12+dfsg-9ubuntu0.1")) flag++;

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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvncclient1 / libvncserver1");
}
