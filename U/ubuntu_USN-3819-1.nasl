#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3819-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(118967);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2018-15471");
  script_xref(name:"USN", value:"3819-1");

  script_name(english:"Ubuntu 18.10 : Linux kernel vulnerability (USN-3819-1)");
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
"Felix Wilhelm discovered that the Xen netback driver in the Linux
kernel did not properly perform input validation in some situations.
An attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3819-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.18-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("ksplice.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(18\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-15471");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3819-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-1003-gcp", pkgver:"4.18.0-1003.4")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-1004-aws", pkgver:"4.18.0-1004.5")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-1004-kvm", pkgver:"4.18.0-1004.4")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-1006-raspi2", pkgver:"4.18.0-1006.8")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-11-generic", pkgver:"4.18.0-11.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-11-generic-lpae", pkgver:"4.18.0-11.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-11-lowlatency", pkgver:"4.18.0-11.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-4.18.0-11-snapdragon", pkgver:"4.18.0-11.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-aws", pkgver:"4.18.0.1004.4")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-gcp", pkgver:"4.18.0.1003.3")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-generic", pkgver:"4.18.0.11.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-generic-lpae", pkgver:"4.18.0.11.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-gke", pkgver:"4.18.0.1003.3")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-kvm", pkgver:"4.18.0.1004.4")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-lowlatency", pkgver:"4.18.0.11.12")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-raspi2", pkgver:"4.18.0.1006.3")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"linux-image-snapdragon", pkgver:"4.18.0.11.12")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.18-aws / linux-image-4.18-gcp / etc");
}