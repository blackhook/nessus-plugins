#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2862. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156336);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id("CVE-2018-12020", "CVE-2019-6690");
  script_xref(name:"IAVA", value:"2018-A-0193");

  script_name(english:"Debian DLA-2862-1 : python-gnupg - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2862 advisory.

  - mainproc.c in GnuPG before 2.2.8 mishandles the original filename during decryption and verification
    actions, which allows remote attackers to spoof the output that GnuPG sends on file descriptor 2 to other
    programs that use the --status-fd 2 option. For example, the OpenPGP data might represent an original
    filename that contains line feed characters in conjunction with GOODSIG or VALIDSIG status codes.
    (CVE-2018-12020)

  - python-gnupg 0.4.3 allows context-dependent attackers to trick gnupg to decrypt other ciphertext than
    intended. To perform the attack, the passphrase to gnupg must be controlled by the adversary and the
    ciphertext should be trusted. Related to a CWE-20: Improper Input Validation issue affecting the affect
    functionality component. (CVE-2019-6690)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/python-gnupg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc0a2eae");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2862");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-12020");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-6690");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/python-gnupg");
  script_set_attribute(attribute:"solution", value:
"Upgrade the python-gnupg packages.

For Debian 9 stretch, these problems have been fixed in version 0.3.9-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6690");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-gnupg");
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
    {'release': '9.0', 'prefix': 'python-gnupg', 'reference': '0.3.9-1+deb9u1'},
    {'release': '9.0', 'prefix': 'python3-gnupg', 'reference': '0.3.9-1+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-gnupg / python3-gnupg');
}
