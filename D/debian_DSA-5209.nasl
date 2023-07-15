#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5209. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164160);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/17");

  script_cve_id(
    "CVE-2022-24805",
    "CVE-2022-24806",
    "CVE-2022-24807",
    "CVE-2022-24808",
    "CVE-2022-24809",
    "CVE-2022-24810"
  );
  script_xref(name:"IAVA", value:"2022-A-0305");

  script_name(english:"Debian DSA-5209-1 : net-snmp - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5209 advisory.

  - The vulnerability exists due to a boundary error when handling INDEX of NET-SNMP-VACM-MIB. A remote
    attacker can trick the victim into loading a specially crafted MIB collection, trigger an out-of-bounds
    write and execute arbitrary code on the target system. (CVE-2022-24805)

  - The vulnerability exists due to insufficient validation of user-supplied input when SETing malformed OIDs
    in master agent and subagent simultaneously. A remote user can pass specially crafted input to the
    application and perform a denial of service (DoS) attack. (CVE-2022-24806)

  - The vulnerability exists due to a boundary error in a SET request to SNMP-VIEW-BASED-ACM-
    MIB::vacmAccessTable. A remote user can pass a malformed OID in a SET request, trigger an out-of-bounds
    write and execute arbitrary code on the target system. (CVE-2022-24807)

  - The vulnerability exists due to a NULL pointer dereference error in NET-SNMP-AGENT-MIB::nsLogTable when
    handling malformed OID in a SET request. A remote user can pass specially crafted data to the application
    and perform a denial of service (DoS) attack. (CVE-2022-24808)

  - The vulnerability exists due to a NULL pointer dereference error in nsVacmAccessTable  when handling
    malformed OID in GET-NEXT. A remote user can pass specially crafted data to the application and perform a
    denial of service (DoS) attack. (CVE-2022-24809)

  - The vulnerability exists due to a NULL pointer dereference error in nsVacmAccessTable when handling
    malformed OID in a SET request. A remote user can pass specially crafted data to the application and
    perform a denial of service (DoS) attack. (CVE-2022-24810)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1016139");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/net-snmp");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5209");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24805");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24806");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24807");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24808");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24809");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24810");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/net-snmp");
  script_set_attribute(attribute:"solution", value:
"Upgrade the net-snmp packages.

For the stable distribution (bullseye), these problems have been fixed in version 5.9+dfsg-4+deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24810");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnetsnmptrapd40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsnmp40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:snmptrapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tkmib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'libnetsnmptrapd40', 'reference': '5.9+dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'libsnmp-base', 'reference': '5.9+dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'libsnmp-dev', 'reference': '5.9+dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'libsnmp-perl', 'reference': '5.9+dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'libsnmp40', 'reference': '5.9+dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'snmp', 'reference': '5.9+dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'snmpd', 'reference': '5.9+dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'snmptrapd', 'reference': '5.9+dfsg-4+deb11u1'},
    {'release': '11.0', 'prefix': 'tkmib', 'reference': '5.9+dfsg-4+deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnetsnmptrapd40 / libsnmp-base / libsnmp-dev / libsnmp-perl / etc');
}
