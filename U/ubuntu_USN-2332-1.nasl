#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2332-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77488);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-0203", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-5077");
  script_bugtraq_id(68125, 68126, 68162, 68163, 68164, 68170, 68224, 68881);
  script_xref(name:"USN", value:"2332-1");

  script_name(english:"Ubuntu 10.04 LTS : linux vulnerabilities (USN-2332-1)");
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
"A bug was discovered in the handling of pathname components when used
with an autofs direct mount. A local user could exploit this flaw to
cause a denial of service (system crash) via an open system call.
(CVE-2014-0203)

Toralf Forster reported an error in the Linux kernels syscall
auditing on 32 bit x86 platforms. A local user could exploit this flaw
to cause a denial of service (OOPS and system crash). (CVE-2014-4508)

An information leak was discovered in the control implemenation of the
Advanced Linux Sound Architecture (ALSA) subsystem in the Linux
kernel. A local user could exploit this flaw to obtain sensitive
information from kernel memory. (CVE-2014-4652)

A use-after-free flaw was discovered in the Advanced Linux Sound
Architecture (ALSA) control implementation of the Linux kernel. A
local user could exploit this flaw to cause a denial of service
(system crash). (CVE-2014-4653)

A authorization bug was discovered with the snd_ctl_elem_add function
of the Advanced Linux Sound Architecture (ALSA) in the Linux kernel. A
local user could exploit his bug to cause a denial of service (remove
kernel controls). (CVE-2014-4654)

A flaw discovered in how the snd_ctl_elem function of the Advanced
Linux Sound Architecture (ALSA) handled a reference count. A local
user could exploit this flaw to cause a denial of service (integer
overflow and limit bypass). (CVE-2014-4655)

An integer overflow flaw was discovered in the control implementation
of the Advanced Linux Sound Architecture (ALSA). A local user could
exploit this flaw to cause a denial of service (system crash).
(CVE-2014-4656)

An integer underflow flaw was discovered in the Linux kernel's
handling of the backlog value for certain SCTP packets. A remote
attacker could exploit this flaw to cause a denial of service (socket
outage) via a crafted SCTP packet. (CVE-2014-4667)

Jason Gunthorpe reported a flaw with SCTP authentication in the Linux
kernel. A remote attacker could exploit this flaw to cause a denial of
service (NULL pointer dereference and OOPS). (CVE-2014-5077).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2332-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-lpia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-versatile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2021 Canonical, Inc. / NASL script (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(10\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 10.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2014-0203", "CVE-2014-4508", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-5077");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-2332-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-65-386", pkgver:"2.6.32-65.131")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-65-generic", pkgver:"2.6.32-65.131")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-65-generic-pae", pkgver:"2.6.32-65.131")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-65-lpia", pkgver:"2.6.32-65.131")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-65-preempt", pkgver:"2.6.32-65.131")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-65-server", pkgver:"2.6.32-65.131")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-65-versatile", pkgver:"2.6.32-65.131")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-65-virtual", pkgver:"2.6.32-65.131")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-386 / linux-image-2.6-generic / etc");
}
