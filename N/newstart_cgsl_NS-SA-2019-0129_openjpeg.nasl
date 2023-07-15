#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0129. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127382);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2016-5139",
    "CVE-2016-5158",
    "CVE-2016-5159",
    "CVE-2016-7163",
    "CVE-2016-9675"
  );

  script_name(english:"NewStart CGSL MAIN 4.05 : openjpeg Multiple Vulnerabilities (NS-SA-2019-0129)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has openjpeg packages installed that are affected by multiple
vulnerabilities:

  - A vulnerability was found in the patch for CVE-2013-6045
    for OpenJPEG. A specially crafted JPEG2000 image, when
    read by an application using OpenJPEG, could cause heap-
    based buffer overflows leading to a crash or possible
    code execution. (CVE-2016-9675)

  - An integer overflow, leading to a heap buffer overflow,
    was found in OpenJPEG. An attacker could create a
    crafted JPEG2000 image that, when loaded by an
    application using openjpeg, could lead to a crash or,
    potentially, code execution. (CVE-2016-7163)

  - An integer overflow, leading to a heap buffer overflow,
    was found in openjpeg, also affecting the PDF viewer in
    Chromium. A specially crafted JPEG2000 image could cause
    an incorrect calculation when allocating memory for code
    blocks, which could lead to a crash, or potentially,
    code execution. (CVE-2016-5159)

  - An integer overflow, leading to a heap buffer overflow,
    was found in openjpeg, also affecting the PDF viewer in
    Chromium. A specially crafted JPEG2000 image could cause
    incorrect calculations when allocating various data
    structures, which could lead to a crash, or potentially,
    code execution. (CVE-2016-5158)

  - An integer overflow, leading to a heap buffer overflow,
    was found in openjpeg, also affecting the PDF viewer in
    Chromium. A specially crafted JPEG2000 image could cause
    an incorrect calculation when allocating precinct data
    structures, which could lead to a crash, or potentially,
    code execution. (CVE-2016-5139)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0129");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL openjpeg packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9675");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-5159");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "openjpeg-1.3-16.el6_8",
    "openjpeg-debuginfo-1.3-16.el6_8",
    "openjpeg-devel-1.3-16.el6_8",
    "openjpeg-libs-1.3-16.el6_8"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openjpeg");
}
