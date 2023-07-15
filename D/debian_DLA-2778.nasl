#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2778. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153965);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id(
    "CVE-2019-19797",
    "CVE-2020-21529",
    "CVE-2020-21530",
    "CVE-2020-21531",
    "CVE-2020-21532",
    "CVE-2020-21533",
    "CVE-2020-21534",
    "CVE-2020-21535",
    "CVE-2020-21675",
    "CVE-2020-21676",
    "CVE-2021-3561",
    "CVE-2021-32280"
  );

  script_name(english:"Debian DLA-2778-1 : fig2dev - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2778 advisory.

  - read_colordef in read.c in Xfig fig2dev 3.2.7b has an out-of-bounds write. (CVE-2019-19797)

  - fig2dev 3.2.7b contains a stack buffer overflow in the bezier_spline function in genepic.c.
    (CVE-2020-21529)

  - fig2dev 3.2.7b contains a segmentation fault in the read_objects function in read.c. (CVE-2020-21530)

  - fig2dev 3.2.7b contains a global buffer overflow in the conv_pattern_index function in gencgm.c.
    (CVE-2020-21531)

  - fig2dev 3.2.7b contains a global buffer overflow in the setfigfont function in genepic.c. (CVE-2020-21532)

  - fig2dev 3.2.7b contains a stack buffer overflow in the read_textobject function in read.c.
    (CVE-2020-21533)

  - fig2dev 3.2.7b contains a global buffer overflow in the get_line function in read.c. (CVE-2020-21534)

  - fig2dev 3.2.7b contains a segmentation fault in the gencgm_start function in gencgm.c. (CVE-2020-21535)

  - A stack-based buffer overflow in the genptk_text component in genptk.c of fig2dev 3.2.7b allows attackers
    to cause a denial of service (DOS) via converting a xfig file into ptk format. (CVE-2020-21675)

  - A stack-based buffer overflow in the genpstrx_text() component in genpstricks.c of fig2dev 3.2.7b allows
    attackers to cause a denial of service (DOS) via converting a xfig file into pstricks format.
    (CVE-2020-21676)

  - An issue was discovered in fig2dev before 3.2.8.. A NULL pointer dereference exists in the function
    compute_closed_spline() located in trans_spline.c. It allows an attacker to cause Denial of Service. The
    fixed version of fig2dev is 3.2.8. (CVE-2021-32280)

  - An Out of Bounds flaw was found fig2dev version 3.2.8a. A flawed bounds check in read_objects() could
    allow an attacker to provide a crafted malicious input causing the application to either crash or in some
    cases cause memory corruption. The highest threat from this vulnerability is to integrity as well as
    system availability. (CVE-2021-3561)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/fig2dev");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2778");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-19797");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21529");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21530");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21531");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21532");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21533");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21534");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21535");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21675");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-21676");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32280");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3561");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/fig2dev");
  script_set_attribute(attribute:"solution", value:
"Upgrade the fig2dev packages.

For Debian 9 stretch, these problems have been fixed in version 1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3561");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fig2dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transfig");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
    {'release': '9.0', 'prefix': 'fig2dev', 'reference': '1:3.2.6a-2+deb9u4'},
    {'release': '9.0', 'prefix': 'transfig', 'reference': '1:3.2.6a-2+deb9u4'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fig2dev / transfig');
}
