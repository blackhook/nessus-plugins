#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6115-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176478);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/30");

  script_cve_id("CVE-2023-32700");
  script_xref(name:"USN", value:"6115-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 / 23.04 : TeX Live vulnerability (USN-6115-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS / 22.10 / 23.04 host has packages installed that are affected by a
vulnerability as referenced in the USN-6115-1 advisory.

  - LuaTeX before 1.17.0 allows execution of arbitrary shell commands when compiling a TeX file obtained from
    an untrusted source. This occurs because luatex-core.lua lets the original io.popen be accessed. This also
    affects TeX Live before 2023 r66984 and MiKTeX before 23.5. (CVE-2023-32700)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6115-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:23.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libkpathsea6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libptexenc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libptexenc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsynctex-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsynctex1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsynctex2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexlua-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexlua52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexlua52-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexlua53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexlua53-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexlua53-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexluajit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtexluajit2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:texlive-binaries");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(18\.04|20\.04|22\.04|22\.10|23\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04 / 22.10 / 23.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'libkpathsea-dev', 'pkgver': '2017.20170613.44572-8ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libkpathsea6', 'pkgver': '2017.20170613.44572-8ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libptexenc-dev', 'pkgver': '2017.20170613.44572-8ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libptexenc1', 'pkgver': '2017.20170613.44572-8ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libsynctex-dev', 'pkgver': '2017.20170613.44572-8ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libsynctex1', 'pkgver': '2017.20170613.44572-8ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libtexlua52', 'pkgver': '2017.20170613.44572-8ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libtexlua52-dev', 'pkgver': '2017.20170613.44572-8ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libtexluajit-dev', 'pkgver': '2017.20170613.44572-8ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libtexluajit2', 'pkgver': '2017.20170613.44572-8ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'texlive-binaries', 'pkgver': '2017.20170613.44572-8ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libkpathsea-dev', 'pkgver': '2019.20190605.51237-3ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libkpathsea6', 'pkgver': '2019.20190605.51237-3ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libptexenc-dev', 'pkgver': '2019.20190605.51237-3ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libptexenc1', 'pkgver': '2019.20190605.51237-3ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libsynctex-dev', 'pkgver': '2019.20190605.51237-3ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libsynctex2', 'pkgver': '2019.20190605.51237-3ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libtexlua53', 'pkgver': '2019.20190605.51237-3ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libtexlua53-dev', 'pkgver': '2019.20190605.51237-3ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libtexluajit-dev', 'pkgver': '2019.20190605.51237-3ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'libtexluajit2', 'pkgver': '2019.20190605.51237-3ubuntu0.1'},
    {'osver': '20.04', 'pkgname': 'texlive-binaries', 'pkgver': '2019.20190605.51237-3ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libkpathsea-dev', 'pkgver': '2021.20210626.59705-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libkpathsea6', 'pkgver': '2021.20210626.59705-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libptexenc-dev', 'pkgver': '2021.20210626.59705-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libptexenc1', 'pkgver': '2021.20210626.59705-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libsynctex-dev', 'pkgver': '2021.20210626.59705-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libsynctex2', 'pkgver': '2021.20210626.59705-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtexlua53', 'pkgver': '2021.20210626.59705-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtexlua53-dev', 'pkgver': '2021.20210626.59705-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtexluajit-dev', 'pkgver': '2021.20210626.59705-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'libtexluajit2', 'pkgver': '2021.20210626.59705-1ubuntu0.1'},
    {'osver': '22.04', 'pkgname': 'texlive-binaries', 'pkgver': '2021.20210626.59705-1ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libkpathsea-dev', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libkpathsea6', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libptexenc-dev', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libptexenc1', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libsynctex-dev', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libsynctex2', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libtexlua-dev', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libtexlua53', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libtexlua53-5', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libtexlua53-dev', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libtexluajit-dev', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'libtexluajit2', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '22.10', 'pkgname': 'texlive-binaries', 'pkgver': '2022.20220321.62855-4ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libkpathsea-dev', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libkpathsea6', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libptexenc-dev', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libptexenc1', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libsynctex-dev', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libsynctex2', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libtexlua-dev', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libtexlua53', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libtexlua53-5', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libtexlua53-dev', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libtexluajit-dev', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'libtexluajit2', 'pkgver': '2022.20220321.62855-5ubuntu0.1'},
    {'osver': '23.04', 'pkgname': 'texlive-binaries', 'pkgver': '2022.20220321.62855-5ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libkpathsea-dev / libkpathsea6 / libptexenc-dev / libptexenc1 / etc');
}
