#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2766. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153741);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/30");

  script_cve_id("CVE-2021-3712");
  script_xref(name:"IAVA", value:"2021-A-0395-S");

  script_name(english:"Debian DLA-2766-1 : openssl - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by a vulnerability as referenced in the dla-2766
advisory.

  - ASN.1 strings are represented internally within OpenSSL as an ASN1_STRING structure which contains a
    buffer holding the string data and a field holding the buffer length. This contrasts with normal C strings
    which are repesented as a buffer for the string data which is terminated with a NUL (0) byte. Although not
    a strict requirement, ASN.1 strings that are parsed using OpenSSL's own d2i functions (and other similar
    parsing functions) as well as any string whose value has been set with the ASN1_STRING_set() function will
    additionally NUL terminate the byte array in the ASN1_STRING structure. However, it is possible for
    applications to directly construct valid ASN1_STRING structures which do not NUL terminate the byte array
    by directly setting the data and length fields in the ASN1_STRING array. This can also happen by using
    the ASN1_STRING_set0() function. Numerous OpenSSL functions that print ASN.1 data have been found to
    assume that the ASN1_STRING byte array will be NUL terminated, even though this is not guaranteed for
    strings that have been directly constructed. Where an application requests an ASN.1 structure to be
    printed, and where that ASN.1 structure contains ASN1_STRINGs that have been directly constructed by the
    application without NUL terminating the data field, then a read buffer overrun can occur. The same thing
    can also occur during name constraints processing of certificates (for example if a certificate has been
    directly constructed by the application instead of loading it via the OpenSSL parsing functions, and the
    certificate contains non NUL terminated ASN1_STRING structures). It can also occur in the
    X509_get1_email(), X509_REQ_get1_email() and X509_get1_ocsp() functions. If a malicious actor can cause an
    application to directly construct an ASN1_STRING and then process it through one of the affected OpenSSL
    functions then this issue could be hit. This might result in a crash (causing a Denial of Service attack).
    It could also result in the disclosure of private memory contents (such as private keys, or sensitive
    plaintext). Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k). Fixed in OpenSSL 1.0.2za (Affected
    1.0.2-1.0.2y). (CVE-2021-3712)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openssl");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2766");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3712");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/openssl");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openssl packages.

For Debian 9 stretch, this problem has been fixed in version 1.1.0l-1~deb9u4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3712");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '9.0', 'prefix': 'libssl-dev', 'reference': '1.1.0l-1~deb9u4'},
    {'release': '9.0', 'prefix': 'libssl-doc', 'reference': '1.1.0l-1~deb9u4'},
    {'release': '9.0', 'prefix': 'libssl1.1', 'reference': '1.1.0l-1~deb9u4'},
    {'release': '9.0', 'prefix': 'openssl', 'reference': '1.1.0l-1~deb9u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libssl-dev / libssl-doc / libssl1.1 / openssl');
}
