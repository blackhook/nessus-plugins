#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1837-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66590);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:29");

  script_cve_id("CVE-2013-3076", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3226", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3230", "CVE-2013-3231", "CVE-2013-3233", "CVE-2013-3234", "CVE-2013-3235");
  script_bugtraq_id(59377, 59380, 59381, 59382, 59383, 59385, 59387, 59388, 59389, 59390, 59393, 59396, 59397, 59398);
  script_xref(name:"USN", value:"1837-1");

  script_name(english:"Ubuntu 13.04 : linux vulnerabilities (USN-1837-1)");
  script_summary(english:"Checks dpkg output for updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Ubuntu host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An information leak was discovered in the Linux kernel's crypto API. A
local user could exploit this flaw to examine potentially sensitive
information from the kernel's stack memory. (CVE-2013-3076)

An information leak was discovered in the Linux kernel's rcvmsg path
for ATM (Asynchronous Transfer Mode). A local user could exploit this
flaw to examine potentially sensitive information from the kernel's
stack memory. (CVE-2013-3222)

An information leak was discovered in the Linux kernel's recvmsg path
for ax25 address family. A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack
memory. (CVE-2013-3223)

An information leak was discovered in the Linux kernel's recvmsg path
for the bluetooth address family. A local user could exploit this flaw
to examine potentially sensitive information from the kernel's stack
memory. (CVE-2013-3224)

An information leak was discovered in the Linux kernel's bluetooth
rfcomm protocol support. A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack
memory. (CVE-2013-3225)

An information leak was discovered in the Linux kernel's bluetooth SCO
sockets implementation. A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack
memory. (CVE-2013-3226)

An information leak was discovered in the Linux kernel's CAIF protocol
implementation. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3227)

An information leak was discovered in the Linux kernel's IRDA
(infrared) support subsystem. A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack
memory. (CVE-2013-3228)

An information leak was discovered in the Linux kernel's s390 - z/VM
support. A local user could exploit this flaw to examine potentially
sensitive information from the kernel's stack memory. (CVE-2013-3229)

An information leak was discovered in the Linux kernel's l2tp (Layer
Two Tunneling Protocol) implementation. A local user could exploit
this flaw to examine potentially sensitive information from the
kernel's stack memory. (CVE-2013-3230)

An information leak was discovered in the Linux kernel's llc (Logical
Link Layer 2) support. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3231)

An information leak was discovered in the Linux kernel's nfc (near
field communication) support. A local user could exploit this flaw to
examine potentially sensitive information from the kernel's stack
memory. (CVE-2013-3233)

An information leak was discovered in the Linux kernel's Rose X.25
protocol layer. A local user could exploit this flaw to examine
potentially sensitive information from the kernel's stack memory.
(CVE-2013-3234)

An information leak was discovered in the Linux kernel's TIPC
(Transparent Inter Process Communication) protocol implementation. A
local user could exploit this flaw to examine potentially sensitive
information from the kernel's stack memory. (CVE-2013-3235).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1837-1/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-image-3.8-generic package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.8-generic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2013-2019 Canonical, Inc. / NASL script (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(13\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 13.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2013-3076", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3226", "CVE-2013-3227", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3230", "CVE-2013-3231", "CVE-2013-3233", "CVE-2013-3234", "CVE-2013-3235");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-1837-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"13.04", pkgname:"linux-image-3.8.0-22-generic", pkgver:"3.8.0-22.33")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.8-generic");
}
