#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0158. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154542);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id(
    "CVE-2019-9278",
    "CVE-2020-0093",
    "CVE-2020-0182",
    "CVE-2020-12767",
    "CVE-2020-13113",
    "CVE-2020-13114"
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : libexif Multiple Vulnerabilities (NS-SA-2021-0158)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has libexif packages installed that are affected
by multiple vulnerabilities:

  - In libexif, there is a possible out of bounds write due to an integer overflow. This could lead to remote
    escalation of privilege in the media content provider with no additional execution privileges needed. User
    interaction is needed for exploitation. Product: AndroidVersions: Android-10Android ID: A-112537774
    (CVE-2019-9278)

  - In exif_data_save_data_entry of exif-data.c, there is a possible out of bounds read due to a missing
    bounds check. This could lead to local information disclosure with no additional execution privileges
    needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-8.0 Android-8.1
    Android-9 Android-10Android ID: A-148705132 (CVE-2020-0093)

  - In exif_entry_get_value of exif-entry.c, there is a possible out of bounds read due to a missing bounds
    check. This could lead to local information disclosure with no additional execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android-10Android ID:
    A-147140917 (CVE-2020-0182)

  - exif_entry_get_value in exif-entry.c in libexif 0.6.21 has a divide-by-zero error. (CVE-2020-12767)

  - An issue was discovered in libexif before 0.6.22. Use of uninitialized memory in EXIF Makernote handling
    could lead to crashes and potential use-after-free conditions. (CVE-2020-13113)

  - An issue was discovered in libexif before 0.6.22. An unrestricted size in handling Canon EXIF MakerNote
    data could lead to consumption of large amounts of compute time for decoding EXIF data. (CVE-2020-13114)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0158");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-9278");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-0093");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-0182");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-12767");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-13113");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-13114");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libexif packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9278");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libexif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libexif-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libexif-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libexif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libexif-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libexif-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'libexif-0.6.22-1.el7',
    'libexif-devel-0.6.22-1.el7',
    'libexif-doc-0.6.22-1.el7'
  ],
  'CGSL MAIN 5.05': [
    'libexif-0.6.22-1.el7',
    'libexif-devel-0.6.22-1.el7',
    'libexif-doc-0.6.22-1.el7'
  ]
};
var pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libexif');
}
