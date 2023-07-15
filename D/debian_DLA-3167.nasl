#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3167. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(166708);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/30");

  script_cve_id("CVE-2022-29458");

  script_name(english:"Debian DLA-3167-1 : ncurses - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3167
advisory.

  - ncurses 6.3 before patch 20220416 has an out-of-bounds read and segmentation violation in convert_strings
    in tinfo/read_entry.c in the terminfo library. (CVE-2022-29458)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ncurses");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3167");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29458");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ncurses");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ncurses packages.

For Debian 10 buster, this problem has been fixed in version 6.1+20181013-2+deb10u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29458");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib32ncurses-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib32ncurses6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib32ncursesw6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib32tinfo6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib64ncurses-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib64ncurses6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib64ncursesw6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lib64tinfo6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libncurses-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libncurses5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libncurses5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libncurses6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libncurses6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libncursesw5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libncursesw5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libncursesw6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libncursesw6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtinfo-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtinfo5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtinfo6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtinfo6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ncurses-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ncurses-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ncurses-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ncurses-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ncurses-term");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'lib32ncurses-dev', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'lib32ncurses6', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'lib32ncursesw6', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'lib32tinfo6', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'lib64ncurses-dev', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'lib64ncurses6', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'lib64ncursesw6', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'lib64tinfo6', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libncurses-dev', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libncurses5', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libncurses5-dev', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libncurses6', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libncurses6-dbg', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libncursesw5', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libncursesw5-dev', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libncursesw6', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libncursesw6-dbg', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libtinfo-dev', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libtinfo5', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libtinfo6', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'libtinfo6-dbg', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'ncurses-base', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'ncurses-bin', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'ncurses-doc', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'ncurses-examples', 'reference': '6.1+20181013-2+deb10u3'},
    {'release': '10.0', 'prefix': 'ncurses-term', 'reference': '6.1+20181013-2+deb10u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'lib32ncurses-dev / lib32ncurses6 / lib32ncursesw6 / lib32tinfo6 / etc');
}
