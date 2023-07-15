#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4369-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(136966);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2019-19377", "CVE-2019-19769", "CVE-2020-11494", "CVE-2020-11565", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668", "CVE-2020-12657");
  script_xref(name:"USN", value:"4369-2");

  script_name(english:"Ubuntu 18.04 LTS / 19.10 : Linux kernel regression (USN-4369-2)");
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
"USN-4369-1 fixed vulnerabilities in the 5.3 Linux kernel.
Unfortunately, that update introduced a regression in overlayfs. This
update corrects the problem.

We apologize for the inconvenience.

It was discovered that the btrfs implementation in the Linux kernel
did not properly detect that a block was marked dirty in some
situations. An attacker could use this to specially craft a file
system image that, when unmounted, could cause a denial of service
(system crash). (CVE-2019-19377)

Tristan Madani discovered that the file locking implementation in the
Linux kernel contained a race condition. A local attacker could
possibly use this to cause a denial of service or expose sensitive
information. (CVE-2019-19769)

It was discovered that the Serial CAN interface driver in the Linux
kernel did not properly initialize data. A local attacker could use
this to expose sensitive information (kernel memory). (CVE-2020-11494)

It was discovered that the linux kernel did not properly validate
certain mount options to the tmpfs virtual memory file system. A local
attacker with the ability to specify mount options could use this to
cause a denial of service (system crash). (CVE-2020-11565)

It was discovered that the OV51x USB Camera device driver in the Linux
kernel did not properly validate device metadata. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2020-11608)

It was discovered that the STV06XX USB Camera device driver in the
Linux kernel did not properly validate device metadata. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2020-11609)

It was discovered that the Xirlink C-It USB Camera device driver in
the Linux kernel did not properly validate device metadata. A
physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2020-11668)

It was discovered that the block layer in the Linux kernel contained a
race condition leading to a use-after-free vulnerability. A local
attacker could possibly use this to cause a denial of service (system
crash) or execute arbitrary code. (CVE-2020-12657).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4369-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19377");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.3-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(18\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2019-19377", "CVE-2019-19769", "CVE-2020-11494", "CVE-2020-11565", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668", "CVE-2020-12657");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-4369-2");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"linux-image-5.3.0-1026-raspi2", pkgver:"5.3.0-1026.28~18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"linux-image-raspi2-hwe-18.04", pkgver:"5.3.0.1026.15")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-1026-raspi2", pkgver:"5.3.0-1026.28")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-55-generic", pkgver:"5.3.0-55.49")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-55-generic-lpae", pkgver:"5.3.0-55.49")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-55-lowlatency", pkgver:"5.3.0-55.49")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-5.3.0-55-snapdragon", pkgver:"5.3.0-55.49")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic", pkgver:"5.3.0.55.47")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-generic-lpae", pkgver:"5.3.0.55.47")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-lowlatency", pkgver:"5.3.0.55.47")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-raspi2", pkgver:"5.3.0.1026.23")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-snapdragon", pkgver:"5.3.0.55.47")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"linux-image-virtual", pkgver:"5.3.0.55.47")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-5.3-generic / linux-image-5.3-generic-lpae / etc");
}
