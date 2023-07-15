#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2771. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153808);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/19");

  script_cve_id(
    "CVE-2018-5729",
    "CVE-2018-5730",
    "CVE-2018-20217",
    "CVE-2021-37750"
  );
  script_xref(name:"IAVB", value:"2021-B-0054-S");

  script_name(english:"Debian DLA-2771-1 : krb5 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2771 advisory.

  - A Reachable Assertion issue was discovered in the KDC in MIT Kerberos 5 (aka krb5) before 1.17. If an
    attacker can obtain a krbtgt ticket using an older encryption type (single-DES, triple-DES, or RC4), the
    attacker can crash the KDC by making an S4U2Self request. (CVE-2018-20217)

  - MIT krb5 1.6 or later allows an authenticated kadmin with permission to add principals to an LDAP Kerberos
    database to cause a denial of service (NULL pointer dereference) or bypass a DN container check by
    supplying tagged data that is internal to the database module. (CVE-2018-5729)

  - MIT krb5 1.6 or later allows an authenticated kadmin with permission to add principals to an LDAP Kerberos
    database to circumvent a DN containership check by supplying both a linkdn and containerdn database
    argument, or by supplying a DN string which is a left extension of a container DN string but is not
    hierarchically within the container DN. (CVE-2018-5730)

  - The Key Distribution Center (KDC) in MIT Kerberos 5 (aka krb5) before 1.18.5 and 1.19.x before 1.19.3 has
    a NULL pointer dereference in kdc/do_tgs_req.c via a FAST inner body that lacks a server field.
    (CVE-2021-37750)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891869");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/krb5");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2771");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-20217");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5729");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5730");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-37750");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/krb5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the krb5 packages.

For Debian 9 stretch, these problems have been fixed in version 1.15-1+deb9u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/01");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdb5-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrad-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrad0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5support0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'krb5-admin-server', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'krb5-doc', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'krb5-gss-samples', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'krb5-k5tls', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'krb5-kdc', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'krb5-kdc-ldap', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'krb5-kpropd', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'krb5-locales', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'krb5-multidev', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'krb5-otp', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'krb5-pkinit', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'krb5-user', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libgssapi-krb5-2', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libgssrpc4', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libk5crypto3', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libkadm5clnt-mit11', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libkadm5srv-mit11', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libkdb5-8', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libkrad-dev', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libkrad0', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libkrb5-3', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libkrb5-dbg', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libkrb5-dev', 'reference': '1.15-1+deb9u3'},
    {'release': '9.0', 'prefix': 'libkrb5support0', 'reference': '1.15-1+deb9u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'krb5-admin-server / krb5-doc / krb5-gss-samples / krb5-k5tls / etc');
}
