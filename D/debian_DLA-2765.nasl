#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2765. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153600);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/20");

  script_cve_id(
    "CVE-2016-10246",
    "CVE-2016-10247",
    "CVE-2017-6060",
    "CVE-2018-10289",
    "CVE-2018-1000036",
    "CVE-2020-19609"
  );

  script_name(english:"Debian DLA-2765-1 : mupdf - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2765 advisory.

  - Buffer overflow in the main function in jstest_main.c in Mujstest in Artifex Software, Inc. MuPDF before
    1.10 allows remote attackers to cause a denial of service (out-of-bounds write) via a crafted file.
    (CVE-2016-10246)

  - Buffer overflow in the my_getline function in jstest_main.c in Mujstest in Artifex Software, Inc. MuPDF
    before 1.10 allows remote attackers to cause a denial of service (out-of-bounds write) via a crafted file.
    (CVE-2016-10247)

  - Stack-based buffer overflow in jstest_main.c in mujstest in Artifex Software, Inc. MuPDF 1.10a allows
    remote attackers to have unspecified impact via a crafted image. (CVE-2017-6060)

  - In MuPDF 1.12.0 and earlier, multiple memory leaks in the PDF parser allow an attacker to cause a denial
    of service (memory leak) via a crafted file. (CVE-2018-1000036)

  - In MuPDF 1.13.0, there is an infinite loop in the fz_skip_space function of the pdf/pdf-xref.c file. A
    remote adversary could leverage this vulnerability to cause a denial of service via a crafted pdf file.
    (CVE-2018-10289)

  - Artifex MuPDF before 1.18.0 has a heap based buffer over-write in tiff_expand_colormap() function when
    parsing TIFF files allowing attackers to cause a denial of service. (CVE-2020-19609)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mupdf");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2765");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2016-10246");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2016-10247");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-6060");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-1000036");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-10289");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-19609");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/mupdf");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mupdf packages.

For Debian 9 stretch, these problems have been fixed in version 1.14.0+ds1-4+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6060");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmupdf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mupdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mupdf-tools");
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
    {'release': '9.0', 'prefix': 'libmupdf-dev', 'reference': '1.14.0+ds1-4+deb9u1'},
    {'release': '9.0', 'prefix': 'mupdf', 'reference': '1.14.0+ds1-4+deb9u1'},
    {'release': '9.0', 'prefix': 'mupdf-tools', 'reference': '1.14.0+ds1-4+deb9u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libmupdf-dev / mupdf / mupdf-tools');
}
