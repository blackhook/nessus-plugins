#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2931. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158647);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/07");

  script_cve_id("CVE-2022-24407");

  script_name(english:"Debian DLA-2931-1 : cyrus-sasl2 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2931
advisory.

  - In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL
    INSERT or UPDATE statement. (CVE-2022-24407)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/cyrus-sasl2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2931");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-24407");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/cyrus-sasl2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the cyrus-sasl2 packages.

For Debian 9 stretch, this problem has been fixed in version 2.1.27~101-g0780600+dfsg-3+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-sasl2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsasl2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsasl2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsasl2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsasl2-modules-db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsasl2-modules-gssapi-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsasl2-modules-gssapi-mit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsasl2-modules-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsasl2-modules-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsasl2-modules-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sasl2-bin");
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
    {'release': '9.0', 'prefix': 'cyrus-sasl2-doc', 'reference': '2.1.27~101-g0780600+dfsg-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libsasl2-2', 'reference': '2.1.27~101-g0780600+dfsg-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libsasl2-dev', 'reference': '2.1.27~101-g0780600+dfsg-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libsasl2-modules', 'reference': '2.1.27~101-g0780600+dfsg-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libsasl2-modules-db', 'reference': '2.1.27~101-g0780600+dfsg-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libsasl2-modules-gssapi-heimdal', 'reference': '2.1.27~101-g0780600+dfsg-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libsasl2-modules-gssapi-mit', 'reference': '2.1.27~101-g0780600+dfsg-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libsasl2-modules-ldap', 'reference': '2.1.27~101-g0780600+dfsg-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libsasl2-modules-otp', 'reference': '2.1.27~101-g0780600+dfsg-3+deb9u2'},
    {'release': '9.0', 'prefix': 'libsasl2-modules-sql', 'reference': '2.1.27~101-g0780600+dfsg-3+deb9u2'},
    {'release': '9.0', 'prefix': 'sasl2-bin', 'reference': '2.1.27~101-g0780600+dfsg-3+deb9u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cyrus-sasl2-doc / libsasl2-2 / libsasl2-dev / libsasl2-modules / etc');
}
