#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3070-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93241);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/12");

  script_cve_id("CVE-2016-1237", "CVE-2016-5244", "CVE-2016-5400", "CVE-2016-5696", "CVE-2016-5728", "CVE-2016-5828", "CVE-2016-5829", "CVE-2016-6197");
  script_xref(name:"USN", value:"3070-2");

  script_name(english:"Ubuntu 16.04 LTS : linux-raspi2 vulnerabilities (USN-3070-2)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A missing permission check when settings ACLs was discovered in nfsd.
A local user could exploit this flaw to gain access to any file by
setting an ACL. (CVE-2016-1237)

Kangjie Lu discovered an information leak in the Reliable Datagram
Sockets (RDS) implementation in the Linux kernel. A local attacker
could use this to obtain potentially sensitive information from kernel
memory. (CVE-2016-5244)

James Patrick-Evans discovered that the airspy USB device driver in
the Linux kernel did not properly handle certain error conditions. An
attacker with physical access could use this to cause a denial of
service (memory consumption). (CVE-2016-5400)

Yue Cao et al discovered a flaw in the TCP implementation's handling
of challenge acks in the Linux kernel. A remote attacker could use
this to cause a denial of service (reset connection) or inject content
into an TCP stream. (CVE-2016-5696)

Pengfei Wang discovered a race condition in the MIC VOP driver in the
Linux kernel. A local attacker could use this to cause a denial of
service (system crash) or obtain potentially sensitive information
from kernel memory. (CVE-2016-5728)

Cyril Bur discovered that on PowerPC platforms, the Linux kernel
mishandled transactional memory state on exec(). A local attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2016-5828)

It was discovered that a heap based buffer overflow existed in the USB
HID driver in the Linux kernel. A local attacker could use this cause
a denial of service (system crash) or possibly execute arbitrary code.
(CVE-2016-5829)

It was discovered that the OverlayFS implementation in the Linux
kernel did not properly verify dentry state before proceeding with
unlink and rename operations. A local attacker could use this to cause
a denial of service (system crash). (CVE-2016-6197).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3070-2/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected linux-image-4.4-raspi2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.4-raspi2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2016-2023 Canonical, Inc. / NASL script (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 16.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2016-1237", "CVE-2016-5244", "CVE-2016-5400", "CVE-2016-5696", "CVE-2016-5728", "CVE-2016-5828", "CVE-2016-5829", "CVE-2016-6197");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-3070-2");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

var flag = 0;

if (ubuntu_check(osver:"16.04", pkgname:"linux-image-4.4.0-1021-raspi2", pkgver:"4.4.0-1021.27")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-4.4-raspi2");
}
