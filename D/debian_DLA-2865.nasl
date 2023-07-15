#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2865. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156386);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id("CVE-2017-11521", "CVE-2018-12584");

  script_name(english:"Debian DLA-2865-1 : resiprocate - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2865 advisory.

  - The SdpContents::Session::Medium::parse function in resip/stack/SdpContents.cxx in reSIProcate 1.10.2
    allows remote attackers to cause a denial of service (memory consumption) by triggering many media
    connections. (CVE-2017-11521)

  - The ConnectionBase::preparseNewBytes function in resip/stack/ConnectionBase.cxx in reSIProcate through
    1.10.2 allows remote attackers to cause a denial of service (buffer overflow) or possibly execute
    arbitrary code when TLS communication is enabled. (CVE-2018-12584)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869404");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/resiprocate");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2865");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-11521");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-12584");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/resiprocate");
  script_set_attribute(attribute:"solution", value:
"Upgrade the resiprocate packages.

For Debian 9 stretch, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12584");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librecon-1.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librecon-1.11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libresiprocate-1.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libresiprocate-1.11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libresiprocate-turn-client-1.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libresiprocate-turn-client-1.11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:repro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:resiprocate-turn-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:resiprocate-turn-server-psql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sipdialer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:telepathy-resiprocate");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'librecon-1.11', 'reference': '1:1.11.0~beta1-3+deb9u2'},
    {'release': '9.0', 'prefix': 'librecon-1.11-dev', 'reference': '1:1.11.0~beta1-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libresiprocate-1.11', 'reference': '1:1.11.0~beta1-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libresiprocate-1.11-dev', 'reference': '1:1.11.0~beta1-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libresiprocate-turn-client-1.11', 'reference': '1:1.11.0~beta1-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libresiprocate-turn-client-1.11-dev', 'reference': '1:1.11.0~beta1-3+deb9u2'},
    {'release': '9.0', 'prefix': 'repro', 'reference': '1:1.11.0~beta1-3+deb9u2'},
    {'release': '9.0', 'prefix': 'resiprocate-turn-server', 'reference': '1:1.11.0~beta1-3+deb9u2'},
    {'release': '9.0', 'prefix': 'resiprocate-turn-server-psql', 'reference': '1:1.11.0~beta1-3+deb9u2'},
    {'release': '9.0', 'prefix': 'sipdialer', 'reference': '1:1.11.0~beta1-3+deb9u2'},
    {'release': '9.0', 'prefix': 'telepathy-resiprocate', 'reference': '1:1.11.0~beta1-3+deb9u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'librecon-1.11 / librecon-1.11-dev / libresiprocate-1.11 / etc');
}
