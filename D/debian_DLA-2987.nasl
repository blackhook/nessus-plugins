#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2987. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(160408);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2019-19221", "CVE-2021-23177", "CVE-2021-31566");

  script_name(english:"Debian DLA-2987-1 : libarchive - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2987 advisory.

  - In Libarchive 3.4.0, archive_wstring_append_from_mbs in archive_string.c has an out-of-bounds read because
    of an incorrect mbrtowc or mbtowc call. For example, bsdtar crashes via a crafted archive.
    (CVE-2019-19221)

  - An improper link resolution flaw while extracting an archive can lead to changing the access control list
    (ACL) of the target of the link. An attacker may provide a malicious archive to a victim user, who would
    trigger this flaw when trying to extract the archive. A local attacker may use this flaw to change the ACL
    of a file on the system and gain more privileges. (CVE-2021-23177)

  - An improper link resolution flaw can occur while extracting an archive leading to changing modes, times,
    access control lists, and flags of a file outside of the archive. An attacker may provide a malicious
    archive to a victim user, who would trigger this flaw when trying to extract the archive. A local attacker
    may use this flaw to gain more privileges in a system. (CVE-2021-31566)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libarchive");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2987");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-19221");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-23177");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-31566");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libarchive");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libarchive packages.

For Debian 9 stretch, these problems have been fixed in version 3.2.2-2+deb9u3.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19221");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-31566");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsdcpio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bsdtar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libarchive-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libarchive-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libarchive13");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'bsdcpio', 'reference': '3.2.2-2+deb9u3'},
    {'release': '9.0', 'prefix': 'bsdtar', 'reference': '3.2.2-2+deb9u3'},
    {'release': '9.0', 'prefix': 'libarchive-dev', 'reference': '3.2.2-2+deb9u3'},
    {'release': '9.0', 'prefix': 'libarchive-tools', 'reference': '3.2.2-2+deb9u3'},
    {'release': '9.0', 'prefix': 'libarchive13', 'reference': '3.2.2-2+deb9u3'}
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
    severity   : SECURITY_NOTE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bsdcpio / bsdtar / libarchive-dev / libarchive-tools / libarchive13');
}
