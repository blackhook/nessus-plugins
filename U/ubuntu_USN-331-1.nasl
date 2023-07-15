#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-331-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27910);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2006-2934", "CVE-2006-2935", "CVE-2006-2936");
  script_bugtraq_id(18847, 19033);
  script_xref(name:"USN", value:"331-1");

  script_name(english:"Ubuntu 6.06 LTS : linux-source-2.6.15 vulnerabilities (USN-331-1)");
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
"A Denial of service vulnerability was reported in iptables' SCTP
conntrack module. On computers which use this iptables module, a
remote attacker could exploit this to trigger a kernel crash.
(CVE-2006-2934)

A buffer overflow has been discovered in the dvd_read_bca() function.
By inserting a specially crafted DVD, USB stick, or similar
automatically mounted removable device, a local user could crash the
machine or potentially even execute arbitrary code with full root
privileges. (CVE-2006-2935)

The ftdi_sio driver for serial USB ports did not limit the amount of
pending data to be written. A local user could exploit this to drain
all available kernel memory and thus render the system unusable.
(CVE-2006-2936)

Additionally, this update fixes a range of bugs.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/331-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2019 Canonical, Inc. / NASL script (C) 2007-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
release = chomp(release);
if (! ereg(pattern:"^(6\.06)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2006-2934", "CVE-2006-2935", "CVE-2006-2936");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-331-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-386", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-686", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-amd64-generic", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-amd64-k8", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-amd64-server", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-amd64-xeon", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-26-server", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-386", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-686", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-amd64-generic", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-amd64-k8", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-amd64-server", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-amd64-xeon", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-26-server", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-26.46")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-26.46")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.15 / linux-headers-2.6 / linux-headers-2.6-386 / etc");
}
