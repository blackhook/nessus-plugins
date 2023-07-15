#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0185. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129912);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2016-3616",
    "CVE-2018-11212",
    "CVE-2018-11213",
    "CVE-2018-11214",
    "CVE-2018-11813",
    "CVE-2018-14498"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : libjpeg-turbo Multiple Vulnerabilities (NS-SA-2019-0185)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has libjpeg-turbo packages installed that are
affected by multiple vulnerabilities:

  - The cjpeg utility in libjpeg allows remote attackers to
    cause a denial of service (NULL pointer dereference and
    application crash) or execute arbitrary code via a
    crafted file. (CVE-2016-3616)

  - libjpeg 9c has a large loop because read_pixel in
    rdtarga.c mishandles EOF. (CVE-2018-11813)

  - An issue was discovered in libjpeg 9a. The
    get_text_gray_row function in rdppm.c allows remote
    attackers to cause a denial of service (Segmentation
    fault) via a crafted file. (CVE-2018-11213)

  - An issue was discovered in libjpeg 9a. The
    get_text_rgb_row function in rdppm.c allows remote
    attackers to cause a denial of service (Segmentation
    fault) via a crafted file. (CVE-2018-11214)

  - An issue was discovered in libjpeg 9a. The alloc_sarray
    function in jmemmgr.c allows remote attackers to cause a
    denial of service (divide-by-zero error) via a crafted
    file. (CVE-2018-11212)

  - get_8bit_row in rdbmp.c in libjpeg-turbo through 1.5.90
    and MozJPEG through 3.3.1 allows attackers to cause a
    denial of service (heap-based buffer over-read and
    application crash) via a crafted 8-bit BMP in which one
    or more of the color indices is out of range for the
    number of palette entries. (CVE-2018-14498)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0185");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libjpeg-turbo packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3616");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "libjpeg-turbo-1.2.90-8.el7",
    "libjpeg-turbo-debuginfo-1.2.90-8.el7",
    "libjpeg-turbo-devel-1.2.90-8.el7",
    "libjpeg-turbo-static-1.2.90-8.el7",
    "libjpeg-turbo-utils-1.2.90-8.el7",
    "turbojpeg-1.2.90-8.el7",
    "turbojpeg-devel-1.2.90-8.el7"
  ],
  "CGSL MAIN 5.04": [
    "libjpeg-turbo-1.2.90-8.el7",
    "libjpeg-turbo-debuginfo-1.2.90-8.el7",
    "libjpeg-turbo-devel-1.2.90-8.el7",
    "libjpeg-turbo-static-1.2.90-8.el7",
    "libjpeg-turbo-utils-1.2.90-8.el7",
    "turbojpeg-1.2.90-8.el7",
    "turbojpeg-devel-1.2.90-8.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libjpeg-turbo");
}
