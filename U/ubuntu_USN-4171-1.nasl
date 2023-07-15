#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4171-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130396);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-11481", "CVE-2019-11482", "CVE-2019-11483", "CVE-2019-11485", "CVE-2019-15790");
  script_xref(name:"USN", value:"4171-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 19.04 / 19.10 : Apport vulnerabilities (USN-4171-1)");
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
"Kevin Backhouse discovered Apport would read its user-controlled
settings file as the root user. This could be used by a local attacker
to possibly crash Apport or have other unspecified consequences.
(CVE-2019-11481)

Sander Bos discovered a race-condition in Apport during core dump
creation. This could be used by a local attacker to generate a crash
report for a privileged process that is readable by an unprivileged
user. (CVE-2019-11482)

Sander Bos discovered Apport mishandled crash dumps originating from
containers. This could be used by a local attacker to generate a crash
report for a privileged process that is readable by an unprivileged
user. (CVE-2019-11483)

Sander Bos discovered Apport mishandled lock-file creation. This could
be used by a local attacker to cause a denial of service against
Apport. (CVE-2019-11485)

Kevin Backhouse discovered Apport read various process-specific files
with elevated privileges during crash dump generation. This could
could be used by a local attacker to generate a crash report for a
privileged process that is readable by an unprivileged user.
(CVE-2019-15790).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4171-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected apport, python-apport and / or python3-apport
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11481");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-apport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-apport");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2019-2023 Canonical, Inc. / NASL script (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(16\.04|18\.04|19\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04 / 18.04 / 19.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"apport", pkgver:"2.20.1-0ubuntu2.20")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python-apport", pkgver:"2.20.1-0ubuntu2.20")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"python3-apport", pkgver:"2.20.1-0ubuntu2.20")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"apport", pkgver:"2.20.9-0ubuntu7.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python-apport", pkgver:"2.20.9-0ubuntu7.8")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"python3-apport", pkgver:"2.20.9-0ubuntu7.8")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"apport", pkgver:"2.20.10-0ubuntu27.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"python-apport", pkgver:"2.20.10-0ubuntu27.2")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"python3-apport", pkgver:"2.20.10-0ubuntu27.2")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"apport", pkgver:"2.20.11-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"python-apport", pkgver:"2.20.11-0ubuntu8.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"python3-apport", pkgver:"2.20.11-0ubuntu8.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apport / python-apport / python3-apport");
}
