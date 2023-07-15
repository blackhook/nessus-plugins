#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4335-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(135896);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-11745", "CVE-2019-11755", "CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764", "CVE-2019-15903", "CVE-2019-17005", "CVE-2019-17008", "CVE-2019-17010", "CVE-2019-17011", "CVE-2019-17012", "CVE-2019-17016", "CVE-2019-17017", "CVE-2019-17022", "CVE-2019-17024", "CVE-2019-17026", "CVE-2019-20503", "CVE-2020-6792", "CVE-2020-6793", "CVE-2020-6794", "CVE-2020-6795", "CVE-2020-6798", "CVE-2020-6800", "CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6811", "CVE-2020-6812", "CVE-2020-6814", "CVE-2020-6819", "CVE-2020-6820", "CVE-2020-6821", "CVE-2020-6822", "CVE-2020-6825");
  script_xref(name:"USN", value:"4335-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0032");
  script_xref(name:"CEA-ID", value:"CEA-2020-0007");

  script_name(english:"Ubuntu 16.04 LTS : Thunderbird vulnerabilities (USN-4335-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues were discovered in Thunderbird. If a user
were tricked in to opening a specially crafted website in a browsing
context, an attacker could potentially exploit these to cause a denial
of service, obtain sensitive information, bypass security
restrictions, bypass same-origin restrictions, conduct cross-site
scripting (XSS) attacks, or execute arbitrary code. (CVE-2019-11757,
CVE-2019-11758, CVE-2019-11759, CVE-2019-11760, CVE-2019-11761,
CVE-2019-11762, CVE-2019-11763, CVE-2019-11764, CVE-2019-17005,
CVE-2019-17008, CVE-2019-17010, CVE-2019-17011, CVE-2019-17012,
CVE-2019-17016, CVE-2019-17017, CVE-2019-17022, CVE-2019-17024,
CVE-2019-17026, CVE-2019-20503, CVE-2020-6798, CVE-2020-6800,
CVE-2020-6805, CVE-2020-6806, CVE-2020-6807, CVE-2020-6812,
CVE-2020-6814, CVE-2020-6819, CVE-2020-6820, CVE-2020-6821,
CVE-2020-6825)

It was discovered that NSS incorrectly handled certain memory
operations. A remote attacker could potentially exploit this to cause
a denial of service, or execute arbitrary code. (CVE-2019-11745)

It was discovered that a specially crafted S/MIME message with an
inner encryption layer could be displayed as having a valid signature
in some circumstances, even if the signer had no access to the
encrypted message. An attacker could potentially exploit this to spoof
the message author. (CVE-2019-11755)

A heap overflow was discovered in the expat library in Thunderbird. If
a user were tricked in to opening a specially crafted message, an
attacker could potentially exploit this to cause a denial of service,
or execute arbitrary code. (CVE-2019-15903)

It was discovered that Message ID calculation was based on
uninitialized data. An attacker could potentially exploit this to
obtain sensitive information. (CVE-2020-6792)

Mutiple security issues were discovered in Thunderbird. If a user were
tricked in to opening a specially crafted message, an attacker could
potentially exploit these to cause a denial of service, obtain
sensitive information, or execute arbitrary code. (CVE-2020-6793,
CVE-2020-6795, CVE-2020-6822)

It was discovered that if a user saved passwords before Thunderbird 60
and then later set a master password, an unencrypted copy of these
passwords would still be accessible. A local user could exploit this
to obtain sensitive information. (CVE-2020-6794)

It was discovered that the Devtools' 'Copy as cURL' feature did
not fully escape website-controlled data. If a user were tricked in to
using the 'Copy as cURL' feature to copy and paste a command with
specially crafted data in to a terminal, an attacker could potentially
exploit this to execute arbitrary commands via command injection.
(CVE-2020-6811).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4335-1/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"thunderbird", pkgver:"1:68.7.0+build1-0ubuntu0.16.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
