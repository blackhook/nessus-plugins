#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2983. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159770);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/17");

  script_cve_id(
    "CVE-2018-10753",
    "CVE-2018-10771",
    "CVE-2019-1010069",
    "CVE-2021-32434",
    "CVE-2021-32435",
    "CVE-2021-32436"
  );

  script_name(english:"Debian DLA-2983-1 : abcm2ps - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-2983 advisory.

  - Stack-based buffer overflow in the delayed_output function in music.c in abcm2ps through 8.13.20 allows
    remote attackers to cause a denial of service (application crash) or possibly have unspecified other
    impact. (CVE-2018-10753)

  - Stack-based buffer overflow in the get_key function in parse.c in abcm2ps through 8.13.20 allows remote
    attackers to cause a denial of service (application crash) or possibly have unspecified other impact.
    (CVE-2018-10771)

  - moinejf abcm2ps 8.13.20 is affected by: Incorrect Access Control. The impact is: Allows attackers to cause
    a denial of service attack via a crafted file. The component is: front.c, function txt_add. The fixed
    version is: after commit commit 08aef597656d065e86075f3d53fda89765845eae. (CVE-2019-1010069)

  - abcm2ps v8.14.11 was discovered to contain an out-of-bounds read in the function calculate_beam at draw.c.
    (CVE-2021-32434)

  - Stack-based buffer overflow in the function get_key in parse.c of abcm2ps v8.14.11 allows remote attackers
    to cause a Denial of Service (DoS) via unspecified vectors. (CVE-2021-32435)

  - An out-of-bounds read in the function write_title() in subs.c of abcm2ps v8.14.11 allows remote attackers
    to cause a Denial of Service (DoS) via unspecified vectors. (CVE-2021-32436)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/abcm2ps");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-2983");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10753");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10771");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-1010069");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32434");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32435");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-32436");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/abcm2ps");
  script_set_attribute(attribute:"solution", value:
"Upgrade the abcm2ps packages.

For Debian 9 stretch, these problems have been fixed in version 7.8.9-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10771");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:abcm2ps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '9.0', 'prefix': 'abcm2ps', 'reference': '7.8.9-1+deb9u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'abcm2ps');
}
