#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3466. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177492);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id("CVE-2021-3468");

  script_name(english:"Debian DLA-3466-1 : avahi - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3466
advisory.

  - A flaw was found in avahi in versions 0.6 up to 0.8. The event used to signal the termination of the
    client connection on the avahi Unix socket is not correctly handled in the client_work function, allowing
    a local attacker to trigger an infinite loop. The highest threat from this vulnerability is to the
    availability of the avahi service, which becomes unresponsive after this flaw is triggered.
    (CVE-2021-3468)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=984938");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/avahi");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3466");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3468");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/avahi");
  script_set_attribute(attribute:"solution", value:
"Upgrade the avahi packages.

For Debian 10 buster, this problem has been fixed in version 0.7-4+deb10u3.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3468");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-discover");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-dnsconfd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-ui-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-avahi-0.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-client-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-common-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-common-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-compat-libdnssd-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-compat-libdnssd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-core7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-gobject-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-ui-gtk3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavahi-ui-gtk3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'avahi-autoipd', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'avahi-daemon', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'avahi-discover', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'avahi-dnsconfd', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'avahi-ui-utils', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'avahi-utils', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'gir1.2-avahi-0.6', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-client-dev', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-client3', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-common-data', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-common-dev', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-common3', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-compat-libdnssd-dev', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-compat-libdnssd1', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-core-dev', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-core7', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-glib-dev', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-glib1', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-gobject-dev', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-gobject0', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-ui-gtk3-0', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'libavahi-ui-gtk3-dev', 'reference': '0.7-4+deb10u3'},
    {'release': '10.0', 'prefix': 'python-avahi', 'reference': '0.7-4+deb10u3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'avahi-autoipd / avahi-daemon / avahi-discover / avahi-dnsconfd / etc');
}
