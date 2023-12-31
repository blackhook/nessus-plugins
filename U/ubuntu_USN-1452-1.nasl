#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1452-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59290);
  script_version("1.10");
  script_cvs_date("Date: 2019/09/19 12:54:28");

  script_cve_id("CVE-2012-1601", "CVE-2012-2123", "CVE-2012-2745");
  script_bugtraq_id(53166, 53488);
  script_xref(name:"USN", value:"1452-1");

  script_name(english:"Ubuntu 11.10 : linux vulnerabilities (USN-1452-1)");
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
"A flaw was found in the Linux kernel's KVM (Kernel Virtual Machine)
virtual cpu setup. An unprivileged local user could exploit this flaw
to crash the system leading to a denial of service. (CVE-2012-1601)

Steve Grubb reported a flaw with Linux fscaps (file system base
capabilities) when used to increase the permissions of a process. For
application on which fscaps are in use a local attacker can disable
address space randomization to make attacking the process with raised
privileges easier. (CVE-2012-2123)

A flaw was found in how the Linux kernel passed the replacement
session keyring to a child process. An unprivileged local user could
exploit this flaw to cause a denial of service (panic).
(CVE-2012-2745).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1452-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-generic-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-3.0-virtual");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2012-2019 Canonical, Inc. / NASL script (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2012-1601", "CVE-2012-2123", "CVE-2012-2745");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for USN-1452-1");
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

flag = 0;

if (ubuntu_check(osver:"11.10", pkgname:"linux-image-3.0.0-20-generic", pkgver:"3.0.0-20.34")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"linux-image-3.0.0-20-generic-pae", pkgver:"3.0.0-20.34")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"linux-image-3.0.0-20-server", pkgver:"3.0.0-20.34")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"linux-image-3.0.0-20-virtual", pkgver:"3.0.0-20.34")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "linux-image-3.0-generic / linux-image-3.0-generic-pae / etc");
}
