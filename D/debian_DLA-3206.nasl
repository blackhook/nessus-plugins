#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3206. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168205);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/05");

  script_cve_id(
    "CVE-2019-14870",
    "CVE-2021-3671",
    "CVE-2021-44758",
    "CVE-2022-3437",
    "CVE-2022-41916",
    "CVE-2022-42898",
    "CVE-2022-44640"
  );

  script_name(english:"Debian DLA-3206-1 : heimdal - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3206 advisory.

  - All Samba versions 4.x.x before 4.9.17, 4.10.x before 4.10.11 and 4.11.x before 4.11.3 have an issue,
    where the S4U (MS-SFU) Kerberos delegation model includes a feature allowing for a subset of clients to be
    opted out of constrained delegation in any way, either S4U2Self or regular Kerberos authentication, by
    forcing all tickets for these clients to be non-forwardable. In AD this is implemented by a user attribute
    delegation_not_allowed (aka not-delegated), which translates to disallow-forwardable. However the Samba AD
    DC does not do that for S4U2Self and does set the forwardable flag even if the impersonated client has the
    not-delegated flag set. (CVE-2019-14870)

  - A null pointer de-reference was found in the way samba kerberos server handled missing sname in TGS-REQ
    (Ticket Granting Server - Request). An authenticated user could use this flaw to crash the samba server.
    (CVE-2021-3671)

  - Heimdal is an implementation of ASN.1/DER, PKIX, and Kerberos. Versions prior to 7.7.1 are vulnerable to a
    denial of service vulnerability in Heimdal's PKI certificate validation library, affecting the KDC (via
    PKINIT) and kinit (via PKINIT), as well as any third-party applications using Heimdal's libhx509. Users
    should upgrade to Heimdal 7.7.1 or 7.8. There are no known workarounds for this issue. (CVE-2022-41916)

  - The vulnerability exists due to a boundary error within the GSSAPI unwrap_des() and unwrap_des3() routines
    of Heimdal. A remote user can send specially crafted data to the application, trigger a heap-based buffer
    overflow and perform a denial of service (DoS) attack. (CVE-2022-3437)

  - The Kerberos libraries used by Samba provide a mechanism for authenticating a user or service by means of
    tickets that can contain Privilege Attribute Certificates (PACs). Both the Heimdal and MIT Kerberos
    libraries, and so the embedded Heimdal shipped by Samba suffer from an integer multiplication overflow
    when calculating how many bytes to allocate for a buffer for the parsed PAC. On a 32-bit system an
    overflow allows placement of 16-byte chunks of entirely attacker- controlled data. (Because the user's
    control over this calculation is limited to an unsigned 32-bit value, 64-bit systems are not impacted).
    The server most vulnerable is the KDC, as it will parse an attacker-controlled PAC in the S4U2Proxy
    handler. The secondary risk is to Kerberos-enabled file server installations in a non-AD realm. A non-AD
    Heimdal KDC controlling such a realm may pass on an attacker-controlled PAC within the service ticket.
    (CVE-2022-42898)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=946786");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/heimdal");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3206");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-14870");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3671");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44758");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3437");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41916");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42898");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-44640");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/heimdal");
  script_set_attribute(attribute:"solution", value:
"Upgrade the heimdal packages.

For Debian 10 buster, these problems have been fixed in version 7.5.0+dfsg-3+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14870");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-44640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libasn1-8-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgssapi3-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhcrypto4-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhdb9-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libheimbase1-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libheimntlm0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libhx509-5-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5clnt7-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkadm5srv8-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkafs0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdc2-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-26-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libotp0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libroken18-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsl0-heimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libwind0-heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
    {'release': '10.0', 'prefix': 'heimdal-clients', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-dev', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-docs', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-kcm', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-kdc', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-multidev', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'heimdal-servers', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libasn1-8-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libgssapi3-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libhcrypto4-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libhdb9-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libheimbase1-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libheimntlm0-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libhx509-5-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libkadm5clnt7-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libkadm5srv8-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libkafs0-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libkdc2-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libkrb5-26-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libotp0-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libroken18-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libsl0-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'libwind0-heimdal', 'reference': '7.5.0+dfsg-3+deb10u1'}
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
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'heimdal-clients / heimdal-dev / heimdal-docs / heimdal-kcm / etc');
}
