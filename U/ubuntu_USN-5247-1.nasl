#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5247-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157143);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-3973",
    "CVE-2021-3974",
    "CVE-2021-3984",
    "CVE-2021-4019",
    "CVE-2021-4069"
  );
  script_xref(name:"USN", value:"5247-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.10 : Vim vulnerabilities (USN-5247-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5247-1 advisory.

  - vim is vulnerable to Heap-based Buffer Overflow (CVE-2021-3973, CVE-2021-3984, CVE-2021-4019)

  - vim is vulnerable to Use After Free (CVE-2021-3974, CVE-2021-4069)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5247-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3973");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-athena");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-gui-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vim-tiny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xxd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'vim', 'pkgver': '2:8.0.1453-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'vim-athena', 'pkgver': '2:8.0.1453-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'vim-common', 'pkgver': '2:8.0.1453-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'vim-gnome', 'pkgver': '2:8.0.1453-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'vim-gtk', 'pkgver': '2:8.0.1453-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'vim-gtk3', 'pkgver': '2:8.0.1453-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'vim-gui-common', 'pkgver': '2:8.0.1453-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'vim-nox', 'pkgver': '2:8.0.1453-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'vim-runtime', 'pkgver': '2:8.0.1453-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'vim-tiny', 'pkgver': '2:8.0.1453-1ubuntu1.8'},
    {'osver': '18.04', 'pkgname': 'xxd', 'pkgver': '2:8.0.1453-1ubuntu1.8'},
    {'osver': '20.04', 'pkgname': 'vim', 'pkgver': '2:8.1.2269-1ubuntu5.6'},
    {'osver': '20.04', 'pkgname': 'vim-athena', 'pkgver': '2:8.1.2269-1ubuntu5.6'},
    {'osver': '20.04', 'pkgname': 'vim-common', 'pkgver': '2:8.1.2269-1ubuntu5.6'},
    {'osver': '20.04', 'pkgname': 'vim-gtk', 'pkgver': '2:8.1.2269-1ubuntu5.6'},
    {'osver': '20.04', 'pkgname': 'vim-gtk3', 'pkgver': '2:8.1.2269-1ubuntu5.6'},
    {'osver': '20.04', 'pkgname': 'vim-gui-common', 'pkgver': '2:8.1.2269-1ubuntu5.6'},
    {'osver': '20.04', 'pkgname': 'vim-nox', 'pkgver': '2:8.1.2269-1ubuntu5.6'},
    {'osver': '20.04', 'pkgname': 'vim-runtime', 'pkgver': '2:8.1.2269-1ubuntu5.6'},
    {'osver': '20.04', 'pkgname': 'vim-tiny', 'pkgver': '2:8.1.2269-1ubuntu5.6'},
    {'osver': '20.04', 'pkgname': 'xxd', 'pkgver': '2:8.1.2269-1ubuntu5.6'},
    {'osver': '21.10', 'pkgname': 'vim', 'pkgver': '2:8.2.2434-3ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'vim-athena', 'pkgver': '2:8.2.2434-3ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'vim-common', 'pkgver': '2:8.2.2434-3ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'vim-gtk', 'pkgver': '2:8.2.2434-3ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'vim-gtk3', 'pkgver': '2:8.2.2434-3ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'vim-gui-common', 'pkgver': '2:8.2.2434-3ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'vim-nox', 'pkgver': '2:8.2.2434-3ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'vim-runtime', 'pkgver': '2:8.2.2434-3ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'vim-tiny', 'pkgver': '2:8.2.2434-3ubuntu3.2'},
    {'osver': '21.10', 'pkgname': 'xxd', 'pkgver': '2:8.2.2434-3ubuntu3.2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vim / vim-athena / vim-common / vim-gnome / vim-gtk / vim-gtk3 / etc');
}
