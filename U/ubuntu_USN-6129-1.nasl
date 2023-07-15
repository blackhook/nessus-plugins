#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6129-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176562);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/05");

  script_cve_id("CVE-2023-1981");
  script_xref(name:"USN", value:"6129-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 : Avahi vulnerability (USN-6129-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 22.10 host has packages installed that are affected by a vulnerability as
referenced in the USN-6129-1 advisory.

  - A vulnerability was found in the avahi library. This flaw allows an unprivileged user to make a dbus call,
    causing the avahi daemon to crash. (CVE-2023-1981)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6129-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1981");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-discover");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-dnsconfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-ui-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-avahi-0.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-client-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-libdnssd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-libdnssd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-gobject-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-ui-gtk3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-ui-gtk3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-avahi");
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
if (! ('20.04' >< os_release || '22.04' >< os_release || '22.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'avahi-autoipd', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'avahi-daemon', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'avahi-discover', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'avahi-dnsconfd', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'avahi-ui-utils', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'avahi-utils', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'gir1.2-avahi-0.6', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-client-dev', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-client3', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-common-data', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-common-dev', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-common3', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-compat-libdnssd-dev', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-compat-libdnssd1', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-core-dev', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-core7', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-glib-dev', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-glib1', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-gobject-dev', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-gobject0', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-ui-gtk3-0', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'libavahi-ui-gtk3-dev', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '20.04', 'pkgname': 'python-avahi', 'pkgver': '0.7-4ubuntu7.2'},
    {'osver': '22.04', 'pkgname': 'avahi-autoipd', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'avahi-daemon', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'avahi-discover', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'avahi-dnsconfd', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'avahi-ui-utils', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'avahi-utils', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'gir1.2-avahi-0.6', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-client-dev', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-client3', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-common-data', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-common-dev', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-common3', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-compat-libdnssd-dev', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-compat-libdnssd1', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-core-dev', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-core7', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-glib-dev', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-glib1', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-gobject-dev', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-gobject0', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-ui-gtk3-0', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'libavahi-ui-gtk3-dev', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.04', 'pkgname': 'python3-avahi', 'pkgver': '0.8-5ubuntu5.1'},
    {'osver': '22.10', 'pkgname': 'avahi-autoipd', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'avahi-daemon', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'avahi-discover', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'avahi-dnsconfd', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'avahi-ui-utils', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'avahi-utils', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'gir1.2-avahi-0.6', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-client-dev', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-client3', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-common-data', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-common-dev', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-common3', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-compat-libdnssd-dev', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-compat-libdnssd1', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-core-dev', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-core7', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-glib-dev', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-glib1', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-gobject-dev', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-gobject0', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-ui-gtk3-0', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'libavahi-ui-gtk3-dev', 'pkgver': '0.8-6ubuntu1.22.10.1'},
    {'osver': '22.10', 'pkgname': 'python3-avahi', 'pkgver': '0.8-6ubuntu1.22.10.1'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'avahi-autoipd / avahi-daemon / avahi-discover / avahi-dnsconfd / etc');
}
