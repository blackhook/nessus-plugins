#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1261-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56853);
  script_version("1.9");
  script_cvs_date("Date: 2019/09/19 12:54:27");

  script_cve_id("CVE-2011-3323", "CVE-2011-3324", "CVE-2011-3325", "CVE-2011-3326", "CVE-2011-3327");
  script_bugtraq_id(49784);
  script_xref(name:"USN", value:"1261-1");

  script_name(english:"Ubuntu 10.04 LTS / 10.10 / 11.04 / 11.10 : quagga vulnerabilities (USN-1261-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Riku Hietamaki, Tuomo Untinen and Jukka Taimisto discovered that
Quagga incorrectly handled Link State Update messages with invalid
lengths. A remote attacker could use this flaw to cause Quagga to
crash, resulting in a denial of service. (CVE-2011-3323)

Riku Hietamaki, Tuomo Untinen and Jukka Taimisto discovered that
Quagga incorrectly handled certain IPv6 Database Description messages.
A remote attacker could use this flaw to cause Quagga to crash,
resulting in a denial of service. (CVE-2011-3324)

Riku Hietamaki, Tuomo Untinen and Jukka Taimisto discovered that
Quagga incorrectly handled certain IPv4 packets. A remote attacker
could use this flaw to cause Quagga to crash, resulting in a denial of
service. (CVE-2011-3325)

Riku Hietamaki, Tuomo Untinen and Jukka Taimisto discovered that
Quagga incorrectly handled invalid Link State Advertisement (LSA)
types. A remote attacker could use this flaw to cause Quagga to crash,
resulting in a denial of service. (CVE-2011-3326)

Riku Hietamaki, Tuomo Untinen and Jukka Taimisto discovered that
Quagga incorrectly handled certain BGP UPDATE messages. A remote
attacker could use this flaw to cause Quagga to crash, or possibly
execute arbitrary code. (CVE-2011-3327).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1261-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quagga package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2019 Canonical, Inc. / NASL script (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"quagga", pkgver:"0.99.15-1ubuntu0.3")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"quagga", pkgver:"0.99.17-1ubuntu0.2")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"quagga", pkgver:"0.99.17-4ubuntu1.1")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"quagga", pkgver:"0.99.18-2ubuntu0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga");
}
