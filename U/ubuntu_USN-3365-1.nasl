#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3365-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101974);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2009-5147", "CVE-2015-1855", "CVE-2015-7551", "CVE-2015-9096", "CVE-2016-2337", "CVE-2016-2339", "CVE-2016-7798");
  script_xref(name:"USN", value:"3365-1");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.04 : ruby1.9.1, ruby2.0, ruby2.3 vulnerabilities (USN-3365-1)");
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
"It was discovered that Ruby DL::dlopen incorrectly handled opening
libraries. An attacker could possibly use this issue to open libraries
with tainted names. This issue only applied to Ubuntu 14.04 LTS.
(CVE-2009-5147)

Tony Arcieri, Jeffrey Walton, and Steffan Ullrich discovered that the
Ruby OpenSSL extension incorrectly handled hostname wildcard matching.
This issue only applied to Ubuntu 14.04 LTS. (CVE-2015-1855)

Christian Hofstaedtler discovered that Ruby Fiddle::Handle incorrectly
handled certain crafted strings. An attacker could use this issue to
cause a denial of service, or possibly execute arbitrary code. This
issue only applied to Ubuntu 14.04 LTS. (CVE-2015-7551)

It was discovered that Ruby Net::SMTP incorrectly handled CRLF
sequences. A remote attacker could possibly use this issue to inject
SMTP commands. (CVE-2015-9096)

Marcin Noga discovered that Ruby incorrectly handled certain arguments
in a TclTkIp class method. An attacker could possibly use this issue
to execute arbitrary code. This issue only affected Ubuntu 14.04 LTS.
(CVE-2016-2337)

It was discovered that Ruby Fiddle::Function.new incorrectly handled
certain arguments. An attacker could possibly use this issue to
execute arbitrary code. This issue only affected Ubuntu 14.04 LTS.
(CVE-2016-2339)

It was discovered that Ruby incorrectly handled the initialization
vector (IV) in GCM mode. An attacker could possibly use this issue to
bypass encryption. (CVE-2016-7798).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3365-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libruby2.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ruby2.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(14\.04|16\.04|17\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"libruby1.9.1", pkgver:"1.9.3.484-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"libruby2.0", pkgver:"2.0.0.484-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"ruby1.9.1", pkgver:"1.9.3.484-2ubuntu1.3")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"ruby2.0", pkgver:"2.0.0.484-1ubuntu2.4")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libruby2.3", pkgver:"2.3.1-2~16.04.2")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"ruby2.3", pkgver:"2.3.1-2~16.04.2")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"libruby2.3", pkgver:"2.3.3-1ubuntu0.1")) flag++;
if (ubuntu_check(osver:"17.04", pkgname:"ruby2.3", pkgver:"2.3.3-1ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libruby1.9.1 / libruby2.0 / libruby2.3 / ruby1.9.1 / ruby2.0 / etc");
}
