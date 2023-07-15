#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2935-3. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90021);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2013-7041", "CVE-2014-2583", "CVE-2015-3238");
  script_xref(name:"USN", value:"2935-3");

  script_name(english:"Ubuntu 12.04 LTS : pam regression (USN-2935-3)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"USN-2935-1 fixed vulnerabilities in PAM. The updates contained a
packaging change that prevented upgrades in certain multiarch
environments. USN-2935-2 intended to fix the problem but was
incomplete for Ubuntu 12.04 LTS. This update fixes the problem in
Ubuntu 12.04 LTS.

We apologize for the inconvenience.

It was discovered that the PAM pam_userdb module incorrectly used a
case-insensitive method when comparing hashed passwords. A local
attacker could possibly use this issue to make brute-force attacks
easier. This issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04
LTS. (CVE-2013-7041)

Sebastian Krahmer discovered that the PAM pam_timestamp
module incorrectly performed filtering. A local attacker
could use this issue to create arbitrary files, or possibly
bypass authentication. This issue only affected Ubuntu 12.04
LTS and Ubuntu 14.04 LTS. (CVE-2014-2583)

Sebastien Macke discovered that the PAM pam_unix module
incorrectly handled large passwords. A local attacker could
possibly use this issue in certain environments to enumerate
usernames or cause a denial of service. (CVE-2015-3238).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2935-3/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libpam-modules package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2023 Canonical, Inc. / NASL script (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
var release = chomp(release);
if (! preg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"libpam-modules", pkgver:"1.1.3-7ubuntu2.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpam-modules");
}
