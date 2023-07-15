#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4250-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133548);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2020-2574");
  script_xref(name:"USN", value:"4250-2");

  script_name(english:"Ubuntu 18.04 LTS / 19.10 : mariadb-10.1, mariadb-10.3 vulnerability (USN-4250-2)");
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
"It was discovered that an unspecified vulnerability existed in the C
API component of MariaDB. An attacker could use this to cause a denial
of service for MariaDB clients.

MariaDB has been updated to 10.3.22 in Ubuntu 19.10 and 10.1.44 in
Ubuntu 18.04 LTS.

In addition to security fixes, the updated packages contain bug fixes,
new features, and possibly incompatible changes.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/4250-2/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadb3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbclient18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libmariadbd19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-core-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-client-core-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-connect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-cracklib-password-check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-gssapi-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-gssapi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-mroonga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-oqgraph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-rocksdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-spider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-plugin-tokudb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-10.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-core-10.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mariadb-server-core-10.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.10");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(18\.04|19\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 19.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"libmariadbclient18", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libmariadbd18", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-client", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-client-10.1", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-client-core-10.1", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-common", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-plugin-connect", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-plugin-cracklib-password-check", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-plugin-gssapi-client", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-plugin-gssapi-server", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-plugin-mroonga", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-plugin-oqgraph", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-plugin-spider", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-plugin-tokudb", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-server", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-server-10.1", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"mariadb-server-core-10.1", pkgver:"1:10.1.44-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libmariadb3", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"libmariadbd19", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-client", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-client-10.3", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-client-core-10.3", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-common", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-plugin-connect", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-plugin-cracklib-password-check", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-plugin-gssapi-client", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-plugin-gssapi-server", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-plugin-mroonga", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-plugin-oqgraph", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-plugin-rocksdb", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-plugin-spider", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-plugin-tokudb", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-server", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-server-10.3", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;
if (ubuntu_check(osver:"19.10", pkgname:"mariadb-server-core-10.3", pkgver:"1:10.3.22-0ubuntu0.19.10.1")) flag++;

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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libmariadb3 / libmariadbclient18 / libmariadbd18 / libmariadbd19 / etc");
}
