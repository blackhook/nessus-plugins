#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2950-5. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91333);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2015-5370", "CVE-2016-2110", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2113", "CVE-2016-2114", "CVE-2016-2115", "CVE-2016-2118");
  script_xref(name:"USN", value:"2950-5");

  script_name(english:"Ubuntu 14.04 LTS / 15.10 / 16.04 LTS : samba regression (USN-2950-5) (Badlock)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"USN-2950-1 fixed vulnerabilities in Samba. USN-2950-3 updated Samba to
version 4.3.9, which introduced a regression when using the ntlm_auth
tool. This update fixes the problem.

Jouni Knuutinen discovered that Samba contained multiple flaws in the
DCE/RPC implementation. A remote attacker could use this issue to
perform a denial of service, downgrade secure connections by
performing a man in the middle attack, or possibly execute arbitrary
code. (CVE-2015-5370)

Stefan Metzmacher discovered that Samba contained multiple
flaws in the NTLMSSP authentication implementation. A remote
attacker could use this issue to downgrade connections to
plain text by performing a man in the middle attack.
(CVE-2016-2110)

Alberto Solino discovered that a Samba domain controller
would establish a secure connection to a server with a
spoofed computer name. A remote attacker could use this
issue to obtain sensitive information. (CVE-2016-2111)

Stefan Metzmacher discovered that the Samba LDAP
implementation did not enforce integrity protection. A
remote attacker could use this issue to hijack LDAP
connections by performing a man in the middle attack.
(CVE-2016-2112)

Stefan Metzmacher discovered that Samba did not validate TLS
certificates. A remote attacker could use this issue to
spoof a Samba server. (CVE-2016-2113)

Stefan Metzmacher discovered that Samba did not enforce SMB
signing even if configured to. A remote attacker could use
this issue to perform a man in the middle attack.
(CVE-2016-2114)

Stefan Metzmacher discovered that Samba did not enable
integrity protection for IPC traffic. A remote attacker
could use this issue to perform a man in the middle attack.
(CVE-2016-2115)

Stefan Metzmacher discovered that Samba incorrectly handled
the MS-SAMR and MS-LSAD protocols. A remote attacker could
use this flaw with a man in the middle attack to impersonate
users and obtain sensitive information from the Security
Account Manager database. This flaw is known as Badlock.
(CVE-2016-2118)

Samba has been updated to 4.3.8 in Ubuntu 14.04 LTS and
Ubuntu 15.10. Ubuntu 12.04 LTS has been updated to 3.6.25
with backported security fixes.

In addition to security fixes, the updated packages contain
bug fixes, new features, and possibly incompatible changes.
Configuration changes may be required in certain
environments.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2950-5/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected samba package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:15.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/26");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (! preg(pattern:"^(14\.04|15\.10|16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 15.10 / 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"samba", pkgver:"2:4.3.9+dfsg-0ubuntu0.14.04.3")) flag++;
if (ubuntu_check(osver:"15.10", pkgname:"samba", pkgver:"2:4.3.9+dfsg-0ubuntu0.15.10.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"samba", pkgver:"2:4.3.9+dfsg-0ubuntu0.16.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
