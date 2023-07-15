#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3845-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119655);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-8784", "CVE-2018-8785", "CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788", "CVE-2018-8789");
  script_xref(name:"USN", value:"3845-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 18.04 LTS / 18.10 : FreeRDP vulnerabilities (USN-3845-1)");
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
"Eyal Itkin discovered FreeRDP incorrectly handled certain stream
encodings. A malicious server could use this issue to cause FreeRDP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only applies to Ubuntu 18.04 LTS and Ubuntu 18.10.
(CVE-2018-8784, CVE-2018-8785)

Eyal Itkin discovered FreeRDP incorrectly handled bitmaps. A malicious
server could use this issue to cause FreeRDP to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2018-8786,
CVE-2018-8787)

Eyal Itkin discovered FreeRDP incorrectly handled certain stream
encodings. A malicious server could use this issue to cause FreeRDP to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only applies to Ubuntu 16.04 LTS, Ubuntu 18.04 LTS
and Ubuntu 18.10. (CVE-2018-8788)

Eyal Itkin discovered FreeRDP incorrectly handled NTLM authentication.
A malicious server could use this issue to cause FreeRDP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
This issue only applies to Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and
Ubuntu 18.10. (CVE-2018-8789).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3845-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-client1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-client2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp2-2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(14\.04|16\.04|18\.04|18\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 18.04 / 18.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"libfreerdp1", pkgver:"1.0.2-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libfreerdp-client1.1", pkgver:"1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.3")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libfreerdp-client2-2", pkgver:"2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libfreerdp2-2", pkgver:"2.0.0~git20170725.1.1648deb+dfsg1-7ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libfreerdp-client2-2", pkgver:"2.0.0~git20180411.1.7a7b1802+dfsg1-2ubuntu0.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libfreerdp2-2", pkgver:"2.0.0~git20180411.1.7a7b1802+dfsg1-2ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfreerdp-client1.1 / libfreerdp-client2-2 / libfreerdp1 / etc");
}
