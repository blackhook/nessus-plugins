#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-2223-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74211);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-4483", "CVE-2014-0055", "CVE-2014-0077", "CVE-2014-0101", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2309", "CVE-2014-2523", "CVE-2014-2672", "CVE-2014-2678", "CVE-2014-2706", "CVE-2014-2851", "CVE-2014-3122");
  script_bugtraq_id(63445, 65943, 66095, 66279, 66441, 66492, 66543, 66591, 66678, 66779, 67162, 67300, 67302);
  script_xref(name:"USN", value:"2223-1");

  script_name(english:"Ubuntu 12.04 LTS : linux-lts-quantal vulnerabilities (USN-2223-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Matthew Daley reported an information leak in the floppy disk driver
of the Linux kernel. An unprivileged local user could exploit this
flaw to obtain potentially sensitive information from kernel memory.
(CVE-2014-1738)

Matthew Daley reported a flaw in the handling of ioctl commands by the
floppy disk driver in the Linux kernel. An unprivileged local user
could exploit this flaw to gain administrative privileges if the
floppy disk module is loaded. (CVE-2014-1737)

A flaw was discovered in the Linux kernel's IPC reference counting. An
unprivileged local user could exploit this flaw to cause a denial of
service (OOM system crash). (CVE-2013-4483)

A flaw was discovered in the vhost-net subsystem of the Linux kernel.
Guest OS users could exploit this flaw to cause a denial of service
(host OS crash). (CVE-2014-0055)

A flaw was discovered in the handling of network packets when
mergeable buffers are disabled for virtual machines in the Linux
kernel. Guest OS users may exploit this flaw to cause a denial of
service (host OS crash) or possibly gain privilege on the host OS.
(CVE-2014-0077)

A flaw was discovered in the Linux kernel's handling of the SCTP
handshake. A remote attacker could exploit this flaw to cause a denial
of service (system crash). (CVE-2014-0101)

A flaw was discovered in the handling of routing information in Linux
kernel's IPv6 stack. A remote attacker could exploit this flaw to
cause a denial of service (memory consumption) via a flood of ICMPv6
router advertisement packets. (CVE-2014-2309)

An error was discovered in the Linux kernel's DCCP protocol support. A
remote attacked could exploit this flaw to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2014-2523)

Max Sydorenko discovered a race condition in the Atheros 9k wireless
driver in the Linux kernel. This race could be exploited by remote
attackers to cause a denial of service (system crash). (CVE-2014-2672)

An error was discovered in the Reliable Datagram Sockets (RDS)
protocol stack in the Linux kernel. A local user could exploit this
flaw to cause a denial of service (system crash) or possibly have
unspecified other impact. (CVE-2014-2678)

Yaara Rozenblum discovered a race condition in the Linux kernel's
Generic IEEE 802.11 Networking Stack (mac80211). Remote attackers
could exploit this flaw to cause a denial of service (system crash).
(CVE-2014-2706)

A flaw was discovered in the Linux kernel's ping sockets. An
unprivileged local user could exploit this flaw to cause a denial of
service (system crash) or possibly gain privileges via a crafted
application. (CVE-2014-2851)

Sasha Levin reported a bug in the Linux kernel's virtual memory
management subsystem. An unprivileged local user could exploit this
flaw to cause a denial of service (system crash). (CVE-2014-3122).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/2223-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-3.5-generic package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.5-generic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2014-2020 Canonical, Inc. / NASL script (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  cve_list = make_list("CVE-2013-4483", "CVE-2014-0055", "CVE-2014-0077", "CVE-2014-0101", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-2309", "CVE-2014-2523", "CVE-2014-2672", "CVE-2014-2678", "CVE-2014-2706", "CVE-2014-2851", "CVE-2014-3122");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-2223-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"linux-image-3.5.0-51-generic", pkgver:"3.5.0-51.76~precise1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.5-generic");
}
