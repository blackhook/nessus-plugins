#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3140. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(165784);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id("CVE-2022-31197");

  script_name(english:"Debian DLA-3140-1 : libpgjava - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3140
advisory.

  - PostgreSQL JDBC Driver (PgJDBC for short) allows Java programs to connect to a PostgreSQL database using
    standard, database independent Java code. The PGJDBC implementation of the
    `java.sql.ResultRow.refreshRow()` method is not performing escaping of column names so a malicious column
    name that contains a statement terminator, e.g. `;`, could lead to SQL injection. This could lead to
    executing additional SQL commands as the application's JDBC user. User applications that do not invoke the
    `ResultSet.refreshRow()` method are not impacted. User application that do invoke that method are impacted
    if the underlying database that they are querying via their JDBC application may be under the control of
    an attacker. The attack requires the attacker to trick the user into executing SQL against a table name
    who's column names would contain the malicious SQL and subsequently invoke the `refreshRow()` method on
    the ResultSet. Note that the application's JDBC user and the schema owner need not be the same. A JDBC
    application that executes as a privileged user querying database schemas owned by potentially malicious
    less-privileged users would be vulnerable. In that situation it may be possible for the malicious user to
    craft a schema that causes the application to execute commands as the privileged user. Patched versions
    will be released as `42.2.26` and `42.4.1`. Users are advised to upgrade. There are no known workarounds
    for this issue. (CVE-2022-31197)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3140");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-31197");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libpgjava");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libpgjava packages.

For Debian 10 Buster, these problems have been fixed in version 42.2.5-2+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31197");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostgresql-jdbc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostgresql-jdbc-java-doc");
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
    {'release': '10.0', 'prefix': 'libpostgresql-jdbc-java', 'reference': '42.2.5-2+deb10u2'},
    {'release': '10.0', 'prefix': 'libpostgresql-jdbc-java-doc', 'reference': '42.2.5-2+deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpostgresql-jdbc-java / libpostgresql-jdbc-java-doc');
}
