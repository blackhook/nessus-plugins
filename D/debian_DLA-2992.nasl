#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2992. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(160475);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2017-12166",
    "CVE-2020-11810",
    "CVE-2020-15078",
    "CVE-2022-0547"
  );
  script_xref(name:"IAVA", value:"2017-A-0285");

  script_name(english:"Debian DLA-2992-1 : openvpn - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-2992 advisory.

  - OpenVPN versions before 2.3.3 and 2.4.x before 2.4.4 are vulnerable to a buffer overflow vulnerability
    when key-method 1 is used, possibly resulting in code execution. (CVE-2017-12166)

  - An issue was discovered in OpenVPN 2.4.x before 2.4.9. An attacker can inject a data channel v2
    (P_DATA_V2) packet using a victim's peer-id. Normally such packets are dropped, but if this packet arrives
    before the data channel crypto parameters have been initialized, the victim's connection will be dropped.
    This requires careful timing due to the small time window (usually within a few seconds) between the
    victim client connection starting and the server PUSH_REPLY response back to the client. This attack will
    only work if Negotiable Cipher Parameters (NCP) is in use. (CVE-2020-11810)

  - OpenVPN 2.5.1 and earlier versions allows a remote attackers to bypass authentication and access control
    channel data on servers configured with deferred authentication, which can be used to potentially trigger
    further information leaks. (CVE-2020-15078)

  - OpenVPN 2.1 until v2.4.12 and v2.5.6 may enable authentication bypass in external authentication plug-ins
    when more than one of them makes use of deferred authentication replies, which allows an external user to
    be granted access with only partially correct credentials. (CVE-2022-0547)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openvpn");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2992");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-12166");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11810");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-15078");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0547");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/openvpn");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openvpn packages.

For Debian 9 stretch, these problems have been fixed in version 2.4.0-6+deb9u4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openvpn");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'openvpn', 'reference': '2.4.0-6+deb9u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openvpn');
}
