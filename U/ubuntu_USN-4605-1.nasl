##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4605-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141932);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2020-15238");
  script_xref(name:"USN", value:"4605-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : Blueman vulnerability (USN-4605-1)");
  script_summary(english:"Checks the dpkg output for the updated package");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has a package installed that is affected by a
vulnerability as referenced in the USN-4605-1 advisory.

  - Blueman is a GTK+ Bluetooth Manager. In Blueman before 2.1.4, the DhcpClient method of the D-Bus interface
    to blueman-mechanism is prone to an argument injection vulnerability. The impact highly depends on the
    system configuration. If Polkit-1 is disabled and for versions lower than 2.0.6, any local user can
    possibly exploit this. If Polkit-1 is enabled for version 2.0.6 and later, a possible attacker needs to be
    allowed to use the `org.blueman.dhcp.client` action. That is limited to users in the wheel group in the
    shipped rules file that do have the privileges anyway. On systems with ISC DHCP client (dhclient),
    attackers can pass arguments to `ip link` with the interface name that can e.g. be used to bring down an
    interface or add an arbitrary XDP/BPF program. On systems with dhcpcd and without ISC DHCP client,
    attackers can even run arbitrary scripts by passing `-c/path/to/script` as an interface name. Patches are
    included in 2.1.4 and master that change the DhcpClient D-Bus method(s) to accept BlueZ network object
    paths instead of network interface names. A backport to 2.0(.8) is also available. As a workaround, make
    sure that Polkit-1-support is enabled and limit privileges for the `org.blueman.dhcp.client` action to
    users that are able to run arbitrary commands as root anyway in /usr/share/polkit-1/rules.d/blueman.rules.
    (CVE-2020-15238)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4605-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected blueman package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15238");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:blueman");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'blueman', 'pkgver': '2.0.4-1ubuntu2.1'},
    {'osver': '18.04', 'pkgname': 'blueman', 'pkgver': '2.0.5-1ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'blueman', 'pkgver': '2.1.2-1ubuntu0.1'},
    {'osver': '20.10', 'pkgname': 'blueman', 'pkgver': '2.1.3-2ubuntu1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'blueman');
}