#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5008-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151452);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2021-3468", "CVE-2021-3502");
  script_xref(name:"USN", value:"5008-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 : Avahi vulnerabilities (USN-5008-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 20.10 / 21.04 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5008-1 advisory.

  - A flaw was found in avahi in versions 0.6 up to 0.8. The event used to signal the termination of the
    client connection on the avahi Unix socket is not correctly handled in the client_work function, allowing
    a local attacker to trigger an infinite loop. The highest threat from this vulnerability is to the
    availability of the avahi service, which becomes unresponsive after this flaw is triggered.
    (CVE-2021-3468)

  - A flaw was found in avahi 0.8-5. A reachable assertion is present in avahi_s_host_name_resolver_start
    function allowing a local attacker to crash the avahi service by requesting hostname resolutions through
    the avahi socket or dbus methods for invalid hostnames. The highest threat from this vulnerability is to
    the service availability. (CVE-2021-3502)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5008-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3502");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-common3-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-libdnssd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-compat-libdnssd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-core7-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-gobject-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-ui-gtk3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavahi-ui-gtk3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-avahi");
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
if (! preg(pattern:"^(18\.04|20\.04|20\.10|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 20.10 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'avahi-autoipd', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'avahi-daemon', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'avahi-discover', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'avahi-dnsconfd', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'avahi-ui-utils', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'avahi-utils', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'gir1.2-avahi-0.6', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-client-dev', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-client3', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-common-data', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-common-dev', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-common3', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-common3-udeb', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-compat-libdnssd-dev', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-compat-libdnssd1', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-core-dev', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-core7', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-core7-udeb', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-glib-dev', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-glib1', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-gobject-dev', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-gobject0', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-ui-gtk3-0', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'libavahi-ui-gtk3-dev', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '18.04', 'pkgname': 'python-avahi', 'pkgver': '0.7-3.1ubuntu1.3'},
    {'osver': '20.04', 'pkgname': 'avahi-autoipd', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'avahi-daemon', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'avahi-discover', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'avahi-dnsconfd', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'avahi-ui-utils', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'avahi-utils', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'gir1.2-avahi-0.6', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-client-dev', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-client3', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-common-data', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-common-dev', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-common3', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-common3-udeb', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-compat-libdnssd-dev', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-compat-libdnssd1', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-core-dev', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-core7', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-core7-udeb', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-glib-dev', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-glib1', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-gobject-dev', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-gobject0', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-ui-gtk3-0', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'libavahi-ui-gtk3-dev', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.04', 'pkgname': 'python-avahi', 'pkgver': '0.7-4ubuntu7.1'},
    {'osver': '20.10', 'pkgname': 'avahi-autoipd', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'avahi-daemon', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'avahi-discover', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'avahi-dnsconfd', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'avahi-ui-utils', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'avahi-utils', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'gir1.2-avahi-0.6', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-client-dev', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-client3', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-common-data', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-common-dev', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-common3', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-compat-libdnssd-dev', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-compat-libdnssd1', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-core-dev', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-core7', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-glib-dev', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-glib1', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-gobject-dev', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-gobject0', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-ui-gtk3-0', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'libavahi-ui-gtk3-dev', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '20.10', 'pkgname': 'python3-avahi', 'pkgver': '0.8-3ubuntu1.1'},
    {'osver': '21.04', 'pkgname': 'avahi-autoipd', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'avahi-daemon', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'avahi-discover', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'avahi-dnsconfd', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'avahi-ui-utils', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'avahi-utils', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'gir1.2-avahi-0.6', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-client-dev', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-client3', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-common-data', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-common-dev', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-common3', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-compat-libdnssd-dev', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-compat-libdnssd1', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-core-dev', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-core7', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-glib-dev', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-glib1', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-gobject-dev', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-gobject0', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-ui-gtk3-0', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'libavahi-ui-gtk3-dev', 'pkgver': '0.8-5ubuntu3.1'},
    {'osver': '21.04', 'pkgname': 'python3-avahi', 'pkgver': '0.8-5ubuntu3.1'}
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
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'avahi-autoipd / avahi-daemon / avahi-discover / avahi-dnsconfd / etc');
}
