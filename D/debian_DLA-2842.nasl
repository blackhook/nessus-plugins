#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2842. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156018);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2021-44228");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/24");
  script_xref(name:"IAVA", value:"2021-A-0573");
  script_xref(name:"IAVA", value:"0001-A-0650");
  script_xref(name:"CEA-ID", value:"CEA-2021-0052");
  script_xref(name:"CEA-ID", value:"CEA-2023-0004");

  script_name(english:"Debian DLA-2842-1 : apache-log4j2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2842
advisory.

  - Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect
    against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log
    messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup
    substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. In previous
    releases (>2.10) this behavior can be mitigated by setting system property log4j2.formatMsgNoLookups to
    true or it can be mitigated in prior releases (<2.10) by removing the JndiLookup class from the
    classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class).
    (CVE-2021-44228)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1001478");
  # https://security-tracker.debian.org/tracker/source-package/apache-log4j2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7f9f2b8");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2842");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44228");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/apache-log4j2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the apache-log4j2 packages.

For Debian 9 stretch, this problem has been fixed in version 2.7-2+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44228");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblog4j2-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblog4j2-java-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'liblog4j2-java', 'reference': '2.7-2+deb9u1'},
    {'release': '9.0', 'prefix': 'liblog4j2-java-doc', 'reference': '2.7-2+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'liblog4j2-java / liblog4j2-java-doc');
}
