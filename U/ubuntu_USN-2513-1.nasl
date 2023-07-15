#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2513-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81567);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-7421", "CVE-2014-7970", "CVE-2014-8160", "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9644", "CVE-2015-0239");
  script_bugtraq_id(70319, 71880, 71883, 71990, 72061, 72320, 72322);
  script_xref(name:"USN", value:"2513-1");

  script_name(english:"Ubuntu 12.04 LTS : linux vulnerabilities (USN-2513-1)");
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
"A flaw was discovered in the Kernel Virtual Machine's (KVM) emulation
of the SYSTENTER instruction when the guest OS does not initialize the
SYSENTER MSRs. A guest OS user could exploit this flaw to cause a
denial of service of the guest OS (crash) or potentially gain
privileges on the guest OS. (CVE-2015-0239)

A flaw was discovered in the automatic loading of modules in the
crypto subsystem of the Linux kernel. A local user could exploit this
flaw to load installed kernel modules, increasing the attack surface
and potentially using this to gain administrative privileges.
(CVE-2013-7421)

Andy Lutomirski discovered a flaw in how the Linux kernel handles
pivot_root when used with a chroot directory. A local user could
exploit this flaw to cause a denial of service (mount-tree loop).
(CVE-2014-7970)

A restriction bypass was discovered in iptables when conntrack rules
are specified and the conntrack protocol handler module is not loaded
into the Linux kernel. This flaw can cause the firewall rules on the
system to be bypassed when conntrack rules are used. (CVE-2014-8160)

A race condition was discovered in the Linux kernel's key ring. A
local user could cause a denial of service (memory corruption or
panic) or possibly have unspecified impact via the keyctl commands.
(CVE-2014-9529)

A memory leak was discovered in the ISO 9660 CDROM file system when
parsing rock ridge ER records. A local user could exploit this flaw to
obtain sensitive information from kernel memory via a crafted iso9660
image. (CVE-2014-9584)

A flaw was discovered in the Address Space Layout Randomization (ASLR)
of the Virtual Dynamically linked Shared Objects (vDSO) location. This
flaw makes it easier for a local user to bypass the ASLR protection
mechanism. (CVE-2014-9585)

A flaw was discovered in the crypto subsystem when screening module
names for automatic module loading if the name contained a valid
crypto module name, eg. vfat(aes). A local user could exploit this
flaw to load installed kernel modules, increasing the attack surface
and potentially using this to gain administrative privileges.
(CVE-2014-9644).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2513-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-highbank");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.2-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2015-2021 Canonical, Inc. / NASL script (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(12\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2013-7421", "CVE-2014-7970", "CVE-2014-8160", "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9644", "CVE-2015-0239");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-2513-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-77-generic", pkgver:"3.2.0-77.112")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-77-generic-pae", pkgver:"3.2.0-77.112")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-77-highbank", pkgver:"3.2.0-77.112")) flag++;
if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.2.0-77-virtual", pkgver:"3.2.0-77.112")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.2-generic / linux-image-3.2-generic-pae / etc");
}
