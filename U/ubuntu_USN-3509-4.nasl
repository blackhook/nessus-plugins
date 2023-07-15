#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3509-4. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105355);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2017-1000405", "CVE-2017-12193", "CVE-2017-16643", "CVE-2017-16939");
  script_xref(name:"USN", value:"3509-4");

  script_name(english:"Ubuntu 14.04 LTS : linux-lts-xenial, linux-aws regression (USN-3509-4) (Dirty COW)");
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
"USN-3509-2 fixed vulnerabilities in the Linux Hardware Enablement
kernel for Ubuntu 14.04 LTS. Unfortunately, it also introduced a
regression that prevented the Ceph network filesystem from being used.
This update fixes the problem.

We apologize for the inconvenience.

Mohamed Ghannam discovered that a use-after-free vulnerability existed
in the Netlink subsystem (XFRM) in the Linux kernel. A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2017-16939)

It was discovered that the Linux kernel did not properly
handle copy-on- write of transparent huge pages. A local
attacker could use this to cause a denial of service
(application crashes) or possibly gain administrative
privileges. (CVE-2017-1000405)

Fan Wu, Haoran Qiu, and Shixiong Zhao discovered that the
associative array implementation in the Linux kernel
sometimes did not properly handle adding a new entry. A
local attacker could use this to cause a denial of service
(system crash). (CVE-2017-12193)

Andrey Konovalov discovered an out-of-bounds read in the
GTCO digitizer USB driver for the Linux kernel. A physically
proximate attacker could use this to cause a denial of
service (system crash) or possibly execute arbitrary code.
(CVE-2017-16643).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3509-4/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-lts-xenial");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2017-2023 Canonical, Inc. / NASL script (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("ksplice.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
var release = chomp(release);
if (! preg(pattern:"^(14\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-1000405", "CVE-2017-12193", "CVE-2017-16643", "CVE-2017-16939");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3509-4");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-1006-aws", pkgver:"4.4.0-1006.6")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-104-generic", pkgver:"4.4.0-104.127~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-104-generic-lpae", pkgver:"4.4.0-104.127~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-4.4.0-104-lowlatency", pkgver:"4.4.0-104.127~14.04.1")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-aws", pkgver:"4.4.0.1006.6")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lpae-lts-xenial", pkgver:"4.4.0.104.87")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-generic-lts-xenial", pkgver:"4.4.0.104.87")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"linux-image-lowlatency-lts-xenial", pkgver:"4.4.0.104.87")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-aws / linux-image-4.4-generic / etc");
}
