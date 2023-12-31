#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1506-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59965);
  script_version("1.9");
  script_cvs_date("Date: 2019/09/19 12:54:28");

  script_cve_id("CVE-2012-3864", "CVE-2012-3865", "CVE-2012-3866", "CVE-2012-3867");
  script_bugtraq_id(54399);
  script_xref(name:"USN", value:"1506-1");

  script_name(english:"Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : puppet vulnerabilities (USN-1506-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Puppet incorrectly handled certain HTTP GET
requests. An attacker could use this flaw with a valid client
certificate to retrieve arbitrary files from the Puppet master.
(CVE-2012-3864)

It was discovered that Puppet incorrectly handled Delete requests. If
a Puppet master were reconfigured to allow the 'Delete' method, an
attacker on an authenticated host could use this flaw to delete
arbitrary files from the Puppet server, leading to a denial of
service. (CVE-2012-3865)

It was discovered that Puppet incorrectly set file permissions on the
last_run_report.yaml file. An attacker could use this flaw to access
sensitive information. This issue only affected Ubuntu 11.10 and
Ubuntu 12.04 LTS. (CVE-2012-3866)

It was discovered that Puppet incorrectly handled agent certificate
names. An attacker could use this flaw to create a specially crafted
certificate and trick an administrator into signing a certificate that
can then be used to man-in-the-middle agent nodes. (CVE-2012-3867).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1506-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected puppet-common package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:puppet-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2019 Canonical, Inc. / NASL script (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
release = chomp(release);
if (! preg(pattern:"^(10\.04|11\.04|11\.10|12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 11.04 / 11.10 / 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"puppet-common", pkgver:"0.25.4-2ubuntu6.8")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"puppet-common", pkgver:"2.6.4-2ubuntu2.10")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"puppet-common", pkgver:"2.7.1-1ubuntu3.7")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"puppet-common", pkgver:"2.7.11-1ubuntu2.1")) flag++;

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
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "puppet-common");
}
