#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-807-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40416);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2009-1389", "CVE-2009-1895", "CVE-2009-2287", "CVE-2009-2406", "CVE-2009-2407");
  script_bugtraq_id(35281, 35529, 35647);
  script_xref(name:"USN", value:"807-1");

  script_name(english:"Ubuntu 6.06 LTS / 8.04 LTS / 8.10 / 9.04 : linux, linux-source-2.6.15 vulnerabilities (USN-807-1)");
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
"Michael Tokarev discovered that the RTL8169 network driver did not
correctly validate buffer sizes. A remote attacker on the local
network could send specially crafted traffic that would crash the
system or potentially grant elevated privileges. (CVE-2009-1389)

Julien Tinnes and Tavis Ormandy discovered that when executing setuid
processes the kernel did not clear certain personality flags. A local
attacker could exploit this to map the NULL memory page, causing other
vulnerabilities to become exploitable. Ubuntu 6.06 was not affected.
(CVE-2009-1895)

Matt T. Yourst discovered that KVM did not correctly validate the page
table root. A local attacker could exploit this to crash the system,
leading to a denial of service. Ubuntu 6.06 was not affected.
(CVE-2009-2287)

Ramon de Carvalho Valle discovered that eCryptfs did not correctly
validate certain buffer sizes. A local attacker could create specially
crafted eCryptfs files to crash the system or gain elevated
privileges. Ubuntu 6.06 was not affected. (CVE-2009-2406,
CVE-2009-2407).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/807-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-doc-2.6.28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-k8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-amd64-xeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpiacompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-openvz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-debug-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-2.6.28");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:6.06:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:9.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2009-2021 Canonical, Inc. / NASL script (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^(6\.06|8\.04|8\.10|9\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 6.06 / 8.04 / 8.10 / 9.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2009-1389", "CVE-2009-1895", "CVE-2009-2287", "CVE-2009-2406", "CVE-2009-2407");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-807-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"6.06", pkgname:"linux-doc-2.6.15", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-386", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-686", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-generic", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-k8", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-server", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-amd64-xeon", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-headers-2.6.15-54-server", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-386", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-686", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-generic", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-k8", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-server", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-amd64-xeon", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-image-2.6.15-54-server", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-kernel-devel", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"6.06", pkgname:"linux-source-2.6.15", pkgver:"2.6.15-54.78")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-doc-2.6.24", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-386", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-generic", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-openvz", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-rt", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-server", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-virtual", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-headers-2.6.24-24-xen", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-386", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-generic", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-lpia", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-lpiacompat", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-openvz", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-rt", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-server", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-virtual", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-2.6.24-24-xen", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-24-386", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-24-generic", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-24-server", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-image-debug-2.6.24-24-virtual", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-kernel-devel", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-libc-dev", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.04", pkgname:"linux-source-2.6.24", pkgver:"2.6.24-24.57")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-doc-2.6.27", pkgver:"2.6.27-14.37")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-14", pkgver:"2.6.27-14.37")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-14-generic", pkgver:"2.6.27-14.37")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-headers-2.6.27-14-server", pkgver:"2.6.27-14.37")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-14-generic", pkgver:"2.6.27-14.37")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-14-server", pkgver:"2.6.27-14.37")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-image-2.6.27-14-virtual", pkgver:"2.6.27-14.37")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-libc-dev", pkgver:"2.6.27-14.37")) flag++;
if (ubuntu_check(osver:"8.10", pkgname:"linux-source-2.6.27", pkgver:"2.6.27-14.37")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-doc-2.6.28", pkgver:"2.6.28-14.47")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-14", pkgver:"2.6.28-14.47")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-14-generic", pkgver:"2.6.28-14.47")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-headers-2.6.28-14-server", pkgver:"2.6.28-14.47")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-14-generic", pkgver:"2.6.28-14.47")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-14-lpia", pkgver:"2.6.28-14.47")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-14-server", pkgver:"2.6.28-14.47")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-14-versatile", pkgver:"2.6.28-14.47")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-image-2.6.28-14-virtual", pkgver:"2.6.28-14.47")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-libc-dev", pkgver:"2.6.28-14.47")) flag++;
if (ubuntu_check(osver:"9.04", pkgname:"linux-source-2.6.28", pkgver:"2.6.28-14.47")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-doc-2.6.15 / linux-doc-2.6.24 / linux-doc-2.6.27 / etc");
}
