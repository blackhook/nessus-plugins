#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3078. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164317);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/20");

  script_cve_id(
    "CVE-2022-23803",
    "CVE-2022-23804",
    "CVE-2022-23946",
    "CVE-2022-23947"
  );

  script_name(english:"Debian DLA-3078-1 : kicad - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3078 advisory.

  - A stack-based buffer overflow vulnerability exists in the Gerber Viewer gerber and excellon ReadXYCoord
    coordinate parsing functionality of KiCad EDA 6.0.1 and master commit de006fc010. A specially-crafted
    gerber or excellon file can lead to code execution. An attacker can provide a malicious file to trigger
    this vulnerability. (CVE-2022-23803)

  - A stack-based buffer overflow vulnerability exists in the Gerber Viewer gerber and excellon ReadIJCoord
    coordinate parsing functionality of KiCad EDA 6.0.1 and master commit de006fc010. A specially-crafted
    gerber or excellon file can lead to code execution. An attacker can provide a malicious file to trigger
    this vulnerability. (CVE-2022-23804)

  - A stack-based buffer overflow vulnerability exists in the Gerber Viewer gerber and excellon GCodeNumber
    parsing functionality of KiCad EDA 6.0.1 and master commit de006fc010. A specially-crafted gerber or
    excellon file can lead to code execution. An attacker can provide a malicious file to trigger this
    vulnerability. (CVE-2022-23946)

  - A stack-based buffer overflow vulnerability exists in the Gerber Viewer gerber and excellon DCodeNumber
    parsing functionality of KiCad EDA 6.0.1 and master commit de006fc010. A specially-crafted gerber or
    excellon file can lead to code execution. An attacker can provide a malicious file to trigger this
    vulnerability. (CVE-2022-23947)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/kicad");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3078");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23803");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23946");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23947");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/kicad");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/kicad");
  script_set_attribute(attribute:"solution", value:
"Upgrade the kicad packages.

For Debian 10 buster, these problems have been fixed in version 5.0.2+dfsg1-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23947");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-doc-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kicad-libraries");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'kicad', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-common', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-demos', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-ca', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-de', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-en', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-es', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-fr', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-id', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-it', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-ja', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-nl', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-pl', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-ru', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-doc-zh', 'reference': '5.0.2+dfsg1-1+deb10u1'},
    {'release': '10.0', 'prefix': 'kicad-libraries', 'reference': '5.0.2+dfsg1-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kicad / kicad-common / kicad-demos / kicad-doc-ca / kicad-doc-de / etc');
}
