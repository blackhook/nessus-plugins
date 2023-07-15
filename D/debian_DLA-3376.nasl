#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3376. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(173788);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2019-6245", "CVE-2019-6247", "CVE-2021-44960");

  script_name(english:"Debian DLA-3376-1 : svgpp - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3376 advisory.

  - An issue was discovered in Anti-Grain Geometry (AGG) 2.4 as used in SVG++ (aka svgpp) 1.2.3. In the
    function agg::cell_aa::not_equal, dx is assigned to (x2 - x1). If dx >= dx_limit, which is (16384 <<
    poly_subpixel_shift), this function will call itself recursively. There can be a situation where (x2 - x1)
    is always bigger than dx_limit during the recursion, leading to continual stack consumption.
    (CVE-2019-6245)

  - An issue was discovered in Anti-Grain Geometry (AGG) 2.4 as used in SVG++ (aka svgpp) 1.2.3. A heap-based
    buffer overflow bug in svgpp_agg_render may lead to code execution. In the render_scanlines_aa_solid
    function, the blend_hline function is called repeatedly multiple times. blend_hline is equivalent to a
    loop containing write operations. Each call writes a piece of heap data, and multiple calls overwrite the
    data in the heap. (CVE-2019-6247)

  - In SVGPP SVG++ library 1.3.0, the XMLDocument::getRoot function in the renderDocument function handled the
    XMLDocument object improperly, returning a null pointer in advance at the second if, resulting in a null
    pointer reference behind the renderDocument function. (CVE-2021-44960)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/svgpp");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3376");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-6245");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-6247");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-44960");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/svgpp");
  script_set_attribute(attribute:"solution", value:
"Upgrade the svgpp packages.

For Debian 10 buster, these problems have been fixed in version 1.2.3+dfsg1-6+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6247");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvgpp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvgpp-doc");
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
    {'release': '10.0', 'prefix': 'libsvgpp-dev', 'reference': '1.2.3+dfsg1-6+deb10u1'},
    {'release': '10.0', 'prefix': 'libsvgpp-doc', 'reference': '1.2.3+dfsg1-6+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsvgpp-dev / libsvgpp-doc');
}
