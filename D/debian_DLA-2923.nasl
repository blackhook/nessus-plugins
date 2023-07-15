#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2923. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158067);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/16");

  script_cve_id("CVE-2021-42392", "CVE-2022-23221");

  script_name(english:"Debian DLA-2923-1 : h2database - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2923 advisory.

  - The org.h2.util.JdbcUtils.getConnection method of the H2 database takes as parameters the class name of
    the driver and URL of the database. An attacker may pass a JNDI driver name and a URL leading to a LDAP or
    RMI servers, causing remote code execution. This can be exploited through various attack vectors, most
    notably through the H2 Console which leads to unauthenticated remote code execution. (CVE-2021-42392)

  - H2 Console before 2.1.210 allows remote attackers to execute arbitrary code via a jdbc:h2:mem JDBC URL
    containing the IGNORE_UNKNOWN_SETTINGS=TRUE;FORBID_CREATION=FALSE;INIT=RUNSCRIPT substring, a different
    vulnerability than CVE-2021-42392. (CVE-2022-23221)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1003894");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/h2database");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2923");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-42392");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23221");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/h2database");
  script_set_attribute(attribute:"solution", value:
"Upgrade the h2database packages.

For Debian 9 stretch, these problems have been fixed in version 1.4.193-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23221");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libh2-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libh2-java-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'libh2-java', 'reference': '1.4.193-1+deb9u1'},
    {'release': '9.0', 'prefix': 'libh2-java-doc', 'reference': '1.4.193-1+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libh2-java / libh2-java-doc');
}
