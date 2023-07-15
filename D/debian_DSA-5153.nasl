#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5153. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(161703);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/31");

  script_cve_id(
    "CVE-2021-37147",
    "CVE-2021-37148",
    "CVE-2021-37149",
    "CVE-2021-38161",
    "CVE-2021-44040",
    "CVE-2021-44759"
  );

  script_name(english:"Debian DSA-5153-1 : trafficserver - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 / 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5153 advisory.

  - Improper input validation vulnerability in header parsing of Apache Traffic Server allows an attacker to
    smuggle requests. This issue affects Apache Traffic Server 8.0.0 to 8.1.2 and 9.0.0 to 9.1.0.
    (CVE-2021-37147)

  - Improper input validation vulnerability in header parsing of Apache Traffic Server allows an attacker to
    smuggle requests. This issue affects Apache Traffic Server 8.0.0 to 8.1.2 and 9.0.0 to 9.0.1.
    (CVE-2021-37148)

  - Improper Input Validation vulnerability in header parsing of Apache Traffic Server allows an attacker to
    smuggle requests. This issue affects Apache Traffic Server 8.0.0 to 8.1.2 and 9.0.0 to 9.1.0.
    (CVE-2021-37149)

  - Improper Authentication vulnerability in TLS origin verification of Apache Traffic Server allows for man
    in the middle attacks. This issue affects Apache Traffic Server 8.0.0 to 8.0.8. (CVE-2021-38161)

  - Improper Input Validation vulnerability in request line parsing of Apache Traffic Server allows an
    attacker to send invalid requests. This issue affects Apache Traffic Server 8.0.0 to 8.1.3 and 9.0.0 to
    9.1.1. (CVE-2021-44040)

  - Improper Authentication vulnerability in TLS origin validation of Apache Traffic Server allows an attacker
    to create a man in the middle attack. This issue affects Apache Traffic Server 8.0.0 to 8.1.0.
    (CVE-2021-44759)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/trafficserver
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20613153");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5153");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37147");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37148");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37149");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-38161");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44040");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44759");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/trafficserver");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/trafficserver");
  script_set_attribute(attribute:"solution", value:
"Upgrade the trafficserver packages.

For the stable distribution (bullseye), these problems have been fixed in version 8.1.1+ds-1.1+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:trafficserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:trafficserver-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:trafficserver-experimental-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(10)\.[0-9]+|^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0 / 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'trafficserver', 'reference': '8.0.2+ds-1+deb10u6'},
    {'release': '10.0', 'prefix': 'trafficserver-dev', 'reference': '8.0.2+ds-1+deb10u6'},
    {'release': '10.0', 'prefix': 'trafficserver-experimental-plugins', 'reference': '8.0.2+ds-1+deb10u6'},
    {'release': '11.0', 'prefix': 'trafficserver', 'reference': '8.1.1+ds-1.1+deb11u1'},
    {'release': '11.0', 'prefix': 'trafficserver-dev', 'reference': '8.1.1+ds-1.1+deb11u1'},
    {'release': '11.0', 'prefix': 'trafficserver-experimental-plugins', 'reference': '8.1.1+ds-1.1+deb11u1'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'trafficserver / trafficserver-dev / trafficserver-experimental-plugins');
}
