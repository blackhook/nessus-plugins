#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5287. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(168145);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2021-3671",
    "CVE-2021-44758",
    "CVE-2022-3437",
    "CVE-2022-41916",
    "CVE-2022-42898",
    "CVE-2022-44640"
  );

  script_name(english:"Debian DSA-5287-1 : heimdal - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5287 advisory.

  - A null pointer de-reference was found in the way samba kerberos server handled missing sname in TGS-REQ
    (Ticket Granting Server - Request). An authenticated user could use this flaw to crash the samba server.
    (CVE-2021-3671)

  - Heimdal before 7.7.1 allows attackers to cause a NULL pointer dereference in a SPNEGO acceptor via a
    preferred_mech_type of GSS_C_NO_OID and a nonzero initial_response value to send_accept. (CVE-2021-44758)

  - A heap-based buffer overflow vulnerability was found in Samba within the GSSAPI unwrap_des() and
    unwrap_des3() routines of Heimdal. The DES and Triple-DES decryption routines in the Heimdal GSSAPI
    library allow a length-limited write buffer overflow on malloc() allocated memory when presented with a
    maliciously small packet. This flaw allows a remote user to send specially crafted malicious data to the
    application, possibly resulting in a denial of service (DoS) attack. (CVE-2022-3437)

  - Heimdal is an implementation of ASN.1/DER, PKIX, and Kerberos. Versions prior to 7.7.1 are vulnerable to a
    denial of service vulnerability in Heimdal's PKI certificate validation library, affecting the KDC (via
    PKINIT) and kinit (via PKINIT), as well as any third-party applications using Heimdal's libhx509. Users
    should upgrade to Heimdal 7.7.1 or 7.8. There are no known workarounds for this issue. (CVE-2022-41916)

  - PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that
    may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit
    platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other
    platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has a similar bug.
    (CVE-2022-42898)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=996586");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/heimdal");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5287");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3671");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44758");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3437");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41916");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42898");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-44640");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/heimdal");
  script_set_attribute(attribute:"solution", value:
"Upgrade the heimdal packages.

For the stable distribution (bullseye), these problems have been fixed in version 7.7.0+dfsg-2+deb11u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3671");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-44640");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/23");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'heimdal-clients', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'heimdal-dev', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'heimdal-docs', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'heimdal-kcm', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'heimdal-kdc', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'heimdal-multidev', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'heimdal-servers', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libasn1-8-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libgssapi3-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libhcrypto4-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libhdb9-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libheimbase1-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libheimntlm0-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libhx509-5-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libkadm5clnt7-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libkadm5srv8-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libkafs0-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libkdc2-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libkrb5-26-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libotp0-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libroken18-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libsl0-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'},
    {'release': '11.0', 'prefix': 'libwind0-heimdal', 'reference': '7.7.0+dfsg-2+deb11u2'}
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
