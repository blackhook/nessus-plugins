#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5312. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(169917);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id(
    "CVE-2022-40149",
    "CVE-2022-40150",
    "CVE-2022-45685",
    "CVE-2022-45693"
  );

  script_name(english:"Debian DSA-5312-1 : libjettison-java - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dsa-5312 advisory.

  - Those using Jettison to parse untrusted XML or JSON data may be vulnerable to Denial of Service attacks
    (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the
    parser to crash by stackoverflow. This effect may support a denial of service attack. (CVE-2022-40149)

  - Those using Jettison to parse untrusted XML or JSON data may be vulnerable to Denial of Service attacks
    (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the
    parser to crash by Out of memory. This effect may support a denial of service attack. (CVE-2022-40150)

  - A stack overflow in Jettison before v1.5.2 allows attackers to cause a Denial of Service (DoS) via crafted
    JSON data. (CVE-2022-45685)

  - Jettison before v1.5.2 was discovered to contain a stack overflow via the map parameter. This
    vulnerability allows attackers to cause a Denial of Service (DoS) via a crafted string. (CVE-2022-45693)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1022553");
  # https://security-tracker.debian.org/tracker/source-package/libjettison-java
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f03db34");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2023/dsa-5312");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40149");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-40150");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45685");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45693");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/libjettison-java");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libjettison-java packages.

For the stable distribution (bullseye), these problems have been fixed in version 1.5.3-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45693");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjettison-java");
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
    {'release': '11.0', 'prefix': 'libjettison-java', 'reference': '1.5.3-1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libjettison-java');
}
