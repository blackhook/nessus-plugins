#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1264-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56861);
  script_version("1.11");
  script_cvs_date("Date: 2019/09/19 12:54:27");

  script_cve_id("CVE-2011-4313");
  script_xref(name:"USN", value:"1264-1");

  script_name(english:"Ubuntu 8.04 LTS / 10.04 LTS / 10.10 / 11.04 / 11.10 : bind9 vulnerability (USN-1264-1)");
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
"It was discovered that Bind incorrectly handled certain specially
crafted packets. A remote attacker could use this flaw to cause Bind
to crash, resulting in a denial of service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/1264-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns66");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdns69");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:10.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:11.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:8.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2011-2019 Canonical, Inc. / NASL script (C) 2011-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(8\.04|10\.04|10\.10|11\.04|11\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 8.04 / 10.04 / 10.10 / 11.04 / 11.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"8.04", pkgname:"libdns36", pkgver:"1:9.4.2.dfsg.P2-2ubuntu0.9")) flag++;
if (ubuntu_check(osver:"10.04", pkgname:"libdns64", pkgver:"1:9.7.0.dfsg.P1-1ubuntu0.4")) flag++;
if (ubuntu_check(osver:"10.10", pkgname:"libdns66", pkgver:"1:9.7.1.dfsg.P2-2ubuntu0.5")) flag++;
if (ubuntu_check(osver:"11.04", pkgname:"libdns69", pkgver:"1:9.7.3.dfsg-1ubuntu2.3")) flag++;
if (ubuntu_check(osver:"11.10", pkgname:"libdns69", pkgver:"1:9.7.3.dfsg-1ubuntu4.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libdns36 / libdns64 / libdns66 / libdns69");
}
