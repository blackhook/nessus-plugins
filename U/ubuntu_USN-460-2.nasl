#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-460-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(28060);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2007-2444");
  script_xref(name:"USN", value:"460-2");

  script_name(english:"Ubuntu 7.04 : samba regression (USN-460-2)");
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
"USN-460-1 fixed several vulnerabilities in Samba. The upstream changes
for CVE-2007-2444 had an unexpected side-effect in Feisty. Shares
configured with the 'force group' option no longer behaved correctly.
This update corrects the problem. We apologize for the inconvenience.

Paul Griffith and Andrew Hogue discovered that Samba did not fully
drop root privileges while translating SIDs. A remote authenticated
user could issue SMB operations during a small window of opportunity
and gain root privileges. (CVE-2007-2444).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/460-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpam-smbpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsmbclient-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:samba-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:smbfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:7.04");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2007-2019 Canonical, Inc. / NASL script (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(7\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 7.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"7.04", pkgname:"libpam-smbpass", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libsmbclient", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"libsmbclient-dev", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"python-samba", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"samba", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"samba-common", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"samba-dbg", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"samba-doc", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"samba-doc-pdf", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"smbclient", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"smbfs", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"swat", pkgver:"3.0.24-2ubuntu1.2")) flag++;
if (ubuntu_check(osver:"7.04", pkgname:"winbind", pkgver:"3.0.24-2ubuntu1.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpam-smbpass / libsmbclient / libsmbclient-dev / python-samba / etc");
}
