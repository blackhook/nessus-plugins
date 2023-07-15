##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4721-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146208);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-21261");
  script_xref(name:"USN", value:"4721-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 : Flatpak vulnerability (USN-4721-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-4721-1 advisory.

  - Flatpak is a system for building, distributing, and running sandboxed desktop applications on Linux. A bug
    was discovered in the `flatpak-portal` service that can allow sandboxed applications to execute arbitrary
    code on the host system (a sandbox escape). This sandbox-escape bug is present in versions from 0.11.4 and
    before fixed versions 1.8.5 and 1.10.0. The Flatpak portal D-Bus service (`flatpak-portal`, also known by
    its D-Bus service name `org.freedesktop.portal.Flatpak`) allows apps in a Flatpak sandbox to launch their
    own subprocesses in a new sandbox instance, either with the same security settings as the caller or with
    more restrictive security settings. For example, this is used in Flatpak-packaged web browsers such as
    Chromium to launch subprocesses that will process untrusted web content, and give those subprocesses a
    more restrictive sandbox than the browser itself. In vulnerable versions, the Flatpak portal service
    passes caller-specified environment variables to non-sandboxed processes on the host system, and in
    particular to the `flatpak run` command that is used to launch the new sandbox instance. A malicious or
    compromised Flatpak app could set environment variables that are trusted by the `flatpak run` command, and
    use them to execute arbitrary code that is not in a sandbox. As a workaround, this vulnerability can be
    mitigated by preventing the `flatpak-portal` service from starting, but that mitigation will prevent many
    Flatpak apps from working correctly. This is fixed in versions 1.8.5 and 1.10.0. (CVE-2021-21261)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4721-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21261");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:flatpak-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-flatpak-1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflatpak-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libflatpak0");
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
if (! preg(pattern:"^(18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'flatpak', 'pkgver': '1.0.9-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'flatpak-tests', 'pkgver': '1.0.9-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'gir1.2-flatpak-1.0', 'pkgver': '1.0.9-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libflatpak-dev', 'pkgver': '1.0.9-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libflatpak0', 'pkgver': '1.0.9-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'flatpak', 'pkgver': '1.6.5-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'flatpak-tests', 'pkgver': '1.6.5-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'gir1.2-flatpak-1.0', 'pkgver': '1.6.5-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libflatpak-dev', 'pkgver': '1.6.5-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libflatpak0', 'pkgver': '1.6.5-0ubuntu0.2'},
    {'osver': '20.10', 'pkgname': 'flatpak', 'pkgver': '1.8.2-1ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'flatpak-tests', 'pkgver': '1.8.2-1ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'gir1.2-flatpak-1.0', 'pkgver': '1.8.2-1ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libflatpak-dev', 'pkgver': '1.8.2-1ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'libflatpak0', 'pkgver': '1.8.2-1ubuntu0.1'}
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
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'flatpak / flatpak-tests / gir1.2-flatpak-1.0 / libflatpak-dev / etc');
}