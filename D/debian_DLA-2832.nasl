#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2832. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155721);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/29");

  script_cve_id(
    "CVE-2019-15945",
    "CVE-2019-15946",
    "CVE-2019-19479",
    "CVE-2020-26570",
    "CVE-2020-26571",
    "CVE-2020-26572"
  );

  script_name(english:"Debian DLA-2832-1 : opensc - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2832 advisory.

  - OpenSC before 0.20.0-rc1 has an out-of-bounds access of an ASN.1 Bitstring in decode_bit_string in
    libopensc/asn1.c. (CVE-2019-15945)

  - OpenSC before 0.20.0-rc1 has an out-of-bounds access of an ASN.1 Octet string in asn1_decode_entry in
    libopensc/asn1.c. (CVE-2019-15946)

  - An issue was discovered in OpenSC through 0.19.0 and 0.20.x through 0.20.0-rc3. libopensc/card-setcos.c
    has an incorrect read operation during parsing of a SETCOS file attribute. (CVE-2019-19479)

  - The Oberthur smart card software driver in OpenSC before 0.21.0-rc1 has a heap-based buffer overflow in
    sc_oberthur_read_file. (CVE-2020-26570)

  - The gemsafe GPK smart card software driver in OpenSC before 0.21.0-rc1 has a stack-based buffer overflow
    in sc_pkcs15emu_gemsafeGPK_init. (CVE-2020-26571)

  - The TCOS smart card software driver in OpenSC before 0.21.0-rc1 has a stack-based buffer overflow in
    tcos_decipher. (CVE-2020-26572)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=939668");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/opensc");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2832");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-15945");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-15946");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-19479");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-26570");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-26571");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-26572");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/opensc");
  script_set_attribute(attribute:"solution", value:
"Upgrade the opensc packages.

For Debian 9 stretch, these problems have been fixed in version 0.16.0-3+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensc-pkcs11");
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
    {'release': '9.0', 'prefix': 'opensc', 'reference': '0.16.0-3+deb9u2'},
    {'release': '9.0', 'prefix': 'opensc-pkcs11', 'reference': '0.16.0-3+deb9u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'opensc / opensc-pkcs11');
}
