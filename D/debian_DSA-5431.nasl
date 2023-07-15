#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5431. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177404);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/17");

  script_cve_id("CVE-2023-32307");

  script_name(english:"Debian DSA-5431-1 : sofia-sip - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by a vulnerability as referenced in the dsa-5431
advisory.

  - Sofia-SIP is an open-source SIP User-Agent library, compliant with the IETF RFC3261 specification.
    Referring to [GHSA-8599-x7rq-fr54](https://github.com/freeswitch/sofia-
    sip/security/advisories/GHSA-8599-x7rq-fr54), several other potential heap-over-flow and integer-overflow
    in stun_parse_attr_error_code and stun_parse_attr_uint32 were found because the lack of attributes length
    check when Sofia-SIP handles STUN packets. The previous patch of [GHSA-8599-x7rq-
    fr54](https://github.com/freeswitch/sofia-sip/security/advisories/GHSA-8599-x7rq-fr54) fixed the
    vulnerability when attr_type did not match the enum value, but there are also vulnerabilities in the
    handling of other valid cases. The OOB read and integer-overflow made by attacker may lead to crash, high
    consumption of memory or even other more serious consequences. These issue have been addressed in version
    1.13.15. Users are advised to upgrade. (CVE-2023-32307)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1036847");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/sofia-sip");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5431");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-32307");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/sofia-sip");
  script_set_attribute(attribute:"solution", value:
"Upgrade the sofia-sip packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32307");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsofia-sip-ua-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsofia-sip-ua-glib-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsofia-sip-ua-glib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsofia-sip-ua0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sofia-sip-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sofia-sip-doc");
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
    {'release': '11.0', 'prefix': 'libsofia-sip-ua-dev', 'reference': '1.12.11+20110422.1-2.1+deb11u2'},
    {'release': '11.0', 'prefix': 'libsofia-sip-ua-glib-dev', 'reference': '1.12.11+20110422.1-2.1+deb11u2'},
    {'release': '11.0', 'prefix': 'libsofia-sip-ua-glib3', 'reference': '1.12.11+20110422.1-2.1+deb11u2'},
    {'release': '11.0', 'prefix': 'libsofia-sip-ua0', 'reference': '1.12.11+20110422.1-2.1+deb11u2'},
    {'release': '11.0', 'prefix': 'sofia-sip-bin', 'reference': '1.12.11+20110422.1-2.1+deb11u2'},
    {'release': '11.0', 'prefix': 'sofia-sip-doc', 'reference': '1.12.11+20110422.1-2.1+deb11u2'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsofia-sip-ua-dev / libsofia-sip-ua-glib-dev / libsofia-sip-ua-glib3 / etc');
}
