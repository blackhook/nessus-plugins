#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2826. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155683);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/23");

  script_cve_id(
    "CVE-2018-9988",
    "CVE-2018-9989",
    "CVE-2020-36475",
    "CVE-2020-36476",
    "CVE-2020-36478",
    "CVE-2021-24119"
  );

  script_name(english:"Debian DLA-2826-1 : mbedtls - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2826 advisory.

  - ARM mbed TLS before 2.1.11, before 2.7.2, and before 2.8.0 has a buffer over-read in
    ssl_parse_server_key_exchange() that could cause a crash on invalid input. (CVE-2018-9988)

  - ARM mbed TLS before 2.1.11, before 2.7.2, and before 2.8.0 has a buffer over-read in
    ssl_parse_server_psk_hint() that could cause a crash on invalid input. (CVE-2018-9989)

  - An issue was discovered in Mbed TLS before 2.25.0 (and before 2.16.9 LTS and before 2.7.18 LTS). The
    calculations performed by mbedtls_mpi_exp_mod are not limited; thus, supplying overly large parameters
    could lead to denial of service when generating Diffie-Hellman key pairs. (CVE-2020-36475)

  - An issue was discovered in Mbed TLS before 2.24.0 (and before 2.16.8 LTS and before 2.7.17 LTS). There is
    missing zeroization of plaintext buffers in mbedtls_ssl_read to erase unused application data from memory.
    (CVE-2020-36476)

  - An issue was discovered in Mbed TLS before 2.25.0 (and before 2.16.9 LTS and before 2.7.18 LTS). A NULL
    algorithm parameters entry looks identical to an array of REAL (size zero) and thus the certificate is
    considered valid. However, if the parameters do not match in any way, then the certificate should be
    considered invalid. (CVE-2020-36478)

  - In Trusted Firmware Mbed TLS 2.24.0, a side-channel vulnerability in base64 PEM file decoding allows
    system-level (administrator) attackers to obtain information about secret RSA keys via a controlled-
    channel and side-channel attack on software running in isolated environments that can be single stepped,
    especially Intel SGX. (CVE-2021-24119)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mbedtls");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2826");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-9988");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-9989");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36475");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36476");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-36478");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-24119");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/mbedtls");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mbedtls packages.

For Debian 9 stretch, these problems have been fixed in version 2.4.2-1+deb9u4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36478");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmbedcrypto0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmbedtls-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmbedtls10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmbedx509-0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
    {'release': '9.0', 'prefix': 'libmbedcrypto0', 'reference': '2.4.2-1+deb9u4'},
    {'release': '9.0', 'prefix': 'libmbedtls-dev', 'reference': '2.4.2-1+deb9u4'},
    {'release': '9.0', 'prefix': 'libmbedtls10', 'reference': '2.4.2-1+deb9u4'},
    {'release': '9.0', 'prefix': 'libmbedx509-0', 'reference': '2.4.2-1+deb9u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmbedcrypto0 / libmbedtls-dev / libmbedtls10 / libmbedx509-0');
}
