#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3213. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168264);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_cve_id("CVE-2022-42898");

  script_name(english:"Debian DLA-3213-1 : krb5 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3213
advisory.

  - krb5: integer overflow vulnerabilities in PAC parsing (CVE-2022-42898)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3213");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42898");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/krb5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the krb5 packages.

For Debian 10 Buster, this problem has been fixed in version 1.17-3+deb10u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42898");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-gss-samples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-k5tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-kpropd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgssapi-krb5-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgssrpc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libk5crypto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5clnt-mit11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5srv-mit11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdb5-9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrad-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrad0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5support0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'krb5-admin-server', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'krb5-doc', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'krb5-gss-samples', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'krb5-k5tls', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'krb5-kdc', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'krb5-kdc-ldap', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'krb5-kpropd', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'krb5-locales', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'krb5-multidev', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'krb5-otp', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'krb5-pkinit', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'krb5-user', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libgssapi-krb5-2', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libgssrpc4', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libk5crypto3', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libkadm5clnt-mit11', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libkadm5srv-mit11', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libkdb5-9', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libkrad-dev', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libkrad0', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libkrb5-3', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libkrb5-dbg', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libkrb5-dev', 'reference': '1.17-3+deb10u5'},
    {'release': '10.0', 'prefix': 'libkrb5support0', 'reference': '1.17-3+deb10u5'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'krb5-admin-server / krb5-doc / krb5-gss-samples / krb5-k5tls / etc');
}
