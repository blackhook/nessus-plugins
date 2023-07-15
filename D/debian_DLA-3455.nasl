#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3455. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177400);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/19");

  script_cve_id("CVE-2019-11840", "CVE-2019-11841", "CVE-2020-9283");

  script_name(english:"Debian DLA-3455-1 : golang-go.crypto - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3455 advisory.

  - An issue was discovered in supplementary Go cryptography libraries, aka golang-googlecode-go-crypto,
    before 2019-03-20. A flaw was found in the amd64 implementation of golang.org/x/crypto/salsa20 and
    golang.org/x/crypto/salsa20/salsa. If more than 256 GiB of keystream is generated, or if the counter
    otherwise grows greater than 32 bits, the amd64 implementation will first generate incorrect output, and
    then cycle back to previously generated keystream. Repeated keystream bytes can lead to loss of
    confidentiality in encryption applications, or to predictability in CSPRNG applications. (CVE-2019-11840)

  - A message-forgery issue was discovered in crypto/openpgp/clearsign/clearsign.go in supplementary Go
    cryptography libraries 2019-03-25. According to the OpenPGP Message Format specification in RFC 4880
    chapter 7, a cleartext signed message can contain one or more optional Hash Armor Headers. The Hash
    Armor Header specifies the message digest algorithm(s) used for the signature. However, the Go clearsign
    package ignores the value of this header, which allows an attacker to spoof it. Consequently, an attacker
    can lead a victim to believe the signature was generated using a different message digest algorithm than
    what was actually used. Moreover, since the library skips Armor Header parsing in general, an attacker can
    not only embed arbitrary Armor Headers, but also prepend arbitrary text to cleartext messages without
    invalidating the signatures. (CVE-2019-11841)

  - golang.org/x/crypto before v0.0.0-20200220183623-bac4c82f6975 for Go allows a panic during signature
    verification in the golang.org/x/crypto/ssh package. A client can attack an SSH server that accepts public
    keys. Also, a server can attack any SSH client. (CVE-2020-9283)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=952462");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3455");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-11840");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-11841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-9283");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/golang-go.crypto");
  # https://security-tracker.debian.org/tracker/source-package/golang-go.crypto
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e94138e5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the golang-go.crypto packages.

For Debian 10 buster, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11841");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-golang-x-crypto-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'golang-golang-x-crypto-dev', 'reference': '1:0.0~git20181203.505ab14-1+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-golang-x-crypto-dev');
}
