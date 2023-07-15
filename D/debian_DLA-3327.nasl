#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3327. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(171786);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/22");

  script_cve_id(
    "CVE-2020-6829",
    "CVE-2020-12400",
    "CVE-2020-12401",
    "CVE-2020-12403",
    "CVE-2023-0767"
  );

  script_name(english:"Debian DLA-3327-1 : nss - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3327 advisory.

  - When converting coordinates from projective to affine, the modular inversion was not performed in constant
    time, resulting in a possible timing-based side channel attack. This vulnerability affects Firefox < 80
    and Firefox for Android < 80. (CVE-2020-12400)

  - During ECDSA signature generation, padding applied in the nonce designed to ensure constant-time scalar
    multiplication was removed, resulting in variable-time execution dependent on secret data. This
    vulnerability affects Firefox < 80 and Firefox for Android < 80. (CVE-2020-12401)

  - A flaw was found in the way CHACHA20-POLY1305 was implemented in NSS in versions before 3.55. When using
    multi-part Chacha20, it could cause out-of-bounds reads. This issue was fixed by explicitly disabling
    multi-part ChaCha20 (which was not functioning correctly) and strictly enforcing tag length. The highest
    threat from this vulnerability is to confidentiality and system availability. (CVE-2020-12403)

  - When performing EC scalar point multiplication, the wNAF point multiplication algorithm was used; which
    leaked partial information about the nonce used during signature generation. Given an electro-magnetic
    trace of a few signature generations, the private key could have been computed. This vulnerability affects
    Firefox < 80 and Firefox for Android < 80. (CVE-2020-6829)

  - An attacker could construct a PKCS 12 cert bundle in such a way that could allow for arbitrary memory
    writes via PKCS 12 Safe Bag attributes being mishandled.  (CVE-2023-0767)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/nss");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3327");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12400");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12401");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-12403");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-6829");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0767");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/nss");
  script_set_attribute(attribute:"solution", value:
"Upgrade the nss packages.

For Debian 10 buster, these problems have been fixed in version 2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12403");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss3-tools");
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
    {'release': '10.0', 'prefix': 'libnss3', 'reference': '2:3.42.1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libnss3-dev', 'reference': '2:3.42.1-1+deb10u6'},
    {'release': '10.0', 'prefix': 'libnss3-tools', 'reference': '2:3.42.1-1+deb10u6'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libnss3 / libnss3-dev / libnss3-tools');
}
