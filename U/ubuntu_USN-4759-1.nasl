##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4759-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147993);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-27218", "CVE-2021-27219");
  script_xref(name:"USN", value:"4759-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : GLib vulnerabilities (USN-4759-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4759-1 advisory.

  - An issue was discovered in GNOME GLib before 2.66.7 and 2.67.x before 2.67.4. If g_byte_array_new_take()
    was called with a buffer of 4GB or more on a 64-bit platform, the length would be truncated modulo 2**32,
    causing unintended length truncation. (CVE-2021-27218)

  - An issue was discovered in GNOME GLib before 2.66.6 and 2.67.x before 2.67.3. The function g_bytes_new has
    an integer overflow on 64-bit platforms due to an implicit cast from 64 bits to 32 bits. The overflow
    could potentially lead to memory corruption. (CVE-2021-27219)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4759-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27219");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgio-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-0-refdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libglib2.0-udeb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'libgio-fam', 'pkgver': '2.48.2-0ubuntu4.7'},
    {'osver': '16.04', 'pkgname': 'libglib2.0-0', 'pkgver': '2.48.2-0ubuntu4.7'},
    {'osver': '16.04', 'pkgname': 'libglib2.0-0-refdbg', 'pkgver': '2.48.2-0ubuntu4.7'},
    {'osver': '16.04', 'pkgname': 'libglib2.0-bin', 'pkgver': '2.48.2-0ubuntu4.7'},
    {'osver': '16.04', 'pkgname': 'libglib2.0-data', 'pkgver': '2.48.2-0ubuntu4.7'},
    {'osver': '16.04', 'pkgname': 'libglib2.0-dev', 'pkgver': '2.48.2-0ubuntu4.7'},
    {'osver': '16.04', 'pkgname': 'libglib2.0-tests', 'pkgver': '2.48.2-0ubuntu4.7'},
    {'osver': '16.04', 'pkgname': 'libglib2.0-udeb', 'pkgver': '2.48.2-0ubuntu4.7'},
    {'osver': '18.04', 'pkgname': 'libgio-fam', 'pkgver': '2.56.4-0ubuntu0.18.04.7'},
    {'osver': '18.04', 'pkgname': 'libglib2.0-0', 'pkgver': '2.56.4-0ubuntu0.18.04.7'},
    {'osver': '18.04', 'pkgname': 'libglib2.0-bin', 'pkgver': '2.56.4-0ubuntu0.18.04.7'},
    {'osver': '18.04', 'pkgname': 'libglib2.0-data', 'pkgver': '2.56.4-0ubuntu0.18.04.7'},
    {'osver': '18.04', 'pkgname': 'libglib2.0-dev', 'pkgver': '2.56.4-0ubuntu0.18.04.7'},
    {'osver': '18.04', 'pkgname': 'libglib2.0-dev-bin', 'pkgver': '2.56.4-0ubuntu0.18.04.7'},
    {'osver': '18.04', 'pkgname': 'libglib2.0-tests', 'pkgver': '2.56.4-0ubuntu0.18.04.7'},
    {'osver': '18.04', 'pkgname': 'libglib2.0-udeb', 'pkgver': '2.56.4-0ubuntu0.18.04.7'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-0', 'pkgver': '2.64.6-1~ubuntu20.04.2'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-bin', 'pkgver': '2.64.6-1~ubuntu20.04.2'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-data', 'pkgver': '2.64.6-1~ubuntu20.04.2'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-dev', 'pkgver': '2.64.6-1~ubuntu20.04.2'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-dev-bin', 'pkgver': '2.64.6-1~ubuntu20.04.2'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-tests', 'pkgver': '2.64.6-1~ubuntu20.04.2'},
    {'osver': '20.04', 'pkgname': 'libglib2.0-udeb', 'pkgver': '2.64.6-1~ubuntu20.04.2'},
    {'osver': '20.10', 'pkgname': 'libglib2.0-0', 'pkgver': '2.66.1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libglib2.0-bin', 'pkgver': '2.66.1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libglib2.0-data', 'pkgver': '2.66.1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libglib2.0-dev', 'pkgver': '2.66.1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libglib2.0-dev-bin', 'pkgver': '2.66.1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libglib2.0-tests', 'pkgver': '2.66.1-2ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libglib2.0-udeb', 'pkgver': '2.66.1-2ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libgio-fam / libglib2.0-0 / libglib2.0-0-refdbg / libglib2.0-bin / etc');
}