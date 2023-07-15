#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2234-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74355);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2013-4387",
    "CVE-2013-4470",
    "CVE-2013-4483",
    "CVE-2014-1438",
    "CVE-2014-3122",
    "CVE-2014-3153"
  );
  script_bugtraq_id(
    62696,
    63359,
    63445,
    64781,
    67162,
    67906
  );
  script_xref(name:"USN", value:"2234-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Ubuntu 10.04 LTS : linux-ec2 vulnerabilities (USN-2234-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"Pinkie Pie discovered a flaw in the Linux kernel's futex subsystem. An
unprivileged local user could exploit this flaw to cause a denial of
service (system crash) or gain administrative privileges.
(CVE-2014-3153)

Dmitry Vyukov reported a flaw in the Linux kernel's handling of IPv6
UDP Fragmentation Offload (UFO) processing. A remote attacker could
leverage this flaw to cause a denial of service (system crash).
(CVE-2013-4387)

Hannes Frederic Sowa discovered a flaw in the Linux kernel's UDP
Fragmentation Offload (UFO). An unprivileged local user could exploit
this flaw to cause a denial of service (system crash) or possibly gain
administrative privileges. (CVE-2013-4470)

A flaw was discovered in the Linux kernel's IPC reference counting. An
unprivileged local user could exploit this flaw to cause a denial of
service (OOM system crash). (CVE-2013-4483)

halfdog reported an error in the AMD K7 and K8 platform support in the
Linux kernel. An unprivileged local user could exploit this flaw on
AMD based systems to cause a denial of service (task kill) or possibly
gain privileges via a crafted application. (CVE-2014-1438)

Sasha Levin reported a bug in the Linux kernel's virtual memory
management subsystem. An unprivileged local user could exploit this
flaw to cause a denial of service (system crash). (CVE-2014-3122).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://usn.ubuntu.com/2234-1/");
  script_set_attribute(attribute:"solution", value:
"Update the affected linux-image-2.6-ec2 package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android "Towelroot" Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-2.6-ec2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  cve_list = make_list("CVE-2013-4387", "CVE-2013-4470", "CVE-2013-4483", "CVE-2014-1438", "CVE-2014-3122", "CVE-2014-3153");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-2234-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"10.04", pkgname:"linux-image-2.6.32-365-ec2", pkgver:"2.6.32-365.79")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-2.6-ec2");
}
