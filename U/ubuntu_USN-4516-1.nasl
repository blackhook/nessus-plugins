#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4516-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140650);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2019-14855");
  script_xref(name:"USN", value:"4516-1");

  script_name(english:"Ubuntu 18.04 LTS : GnuPG vulnerability (USN-4516-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by a vulnerability as referenced in the
USN-4516-1 advisory.

  - A flaw was found in the way certificate signatures could be forged using collisions found in the SHA-1
    algorithm. An attacker could use this weakness to create forged certificate signatures. This issue affects
    GnuPG versions before 2.2.18. (CVE-2019-14855)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4516-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14855");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dirmngr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg-l10n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gnupg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpg-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpg-wks-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpg-wks-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgv-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgv-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgv-win32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gpgv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:scdaemon");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'dirmngr', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gnupg', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gnupg-agent', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gnupg-l10n', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gnupg-utils', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gnupg2', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gpg', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gpg-agent', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gpg-wks-client', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gpg-wks-server', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gpgconf', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gpgsm', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gpgv', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gpgv-static', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gpgv-udeb', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gpgv-win32', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gpgv2', 'pkgver': '2.2.4-1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'scdaemon', 'pkgver': '2.2.4-1ubuntu1.3'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dirmngr / gnupg / gnupg-agent / gnupg-l10n / gnupg-utils / gnupg2 / etc');
}
