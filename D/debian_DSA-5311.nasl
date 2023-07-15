#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5311. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(169698);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/09");

  script_cve_id("CVE-2022-32749", "CVE-2022-37392");

  script_name(english:"Debian DSA-5311-1 : trafficserver - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5311 advisory.

  - Improper Check for Unusual or Exceptional Conditions vulnerability handling requests in Apache Traffic
    Server allows an attacker to crash the server under certain conditions. This issue affects Apache Traffic
    Server: from 8.0.0 through 9.1.3. (CVE-2022-32749)

  - Improper Check for Unusual or Exceptional Conditions vulnerability in handling the requests to Apache
    Traffic Server. This issue affects Apache Traffic Server 8.0.0 to 9.1.2. (CVE-2022-37392)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/trafficserver
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20613153");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5311");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32749");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-37392");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/trafficserver");
  script_set_attribute(attribute:"solution", value:
"Upgrade the trafficserver packages.

For the stable distribution (bullseye), these problems have been fixed in version 8.1.6+ds-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:trafficserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:trafficserver-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:trafficserver-experimental-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'trafficserver', 'reference': '8.1.6+ds-1~deb11u1'},
    {'release': '11.0', 'prefix': 'trafficserver-dev', 'reference': '8.1.6+ds-1~deb11u1'},
    {'release': '11.0', 'prefix': 'trafficserver-experimental-plugins', 'reference': '8.1.6+ds-1~deb11u1'}
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
