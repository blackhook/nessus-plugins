##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0060. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147382);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/11");

  script_cve_id(
    "CVE-2019-2126",
    "CVE-2019-9232",
    "CVE-2019-9371",
    "CVE-2019-9433"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : libvpx Multiple Vulnerabilities (NS-SA-2021-0060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has libvpx packages installed that are affected by multiple
vulnerabilities:

  - In libvpx, there is a possible out of bounds read due to a missing bounds check. This could lead to remote
    information disclosure with no additional execution privileges needed. User interaction is not needed for
    exploitation. Product: AndroidVersions: Android-10Android ID: A-122675483 (CVE-2019-9232)

  - In libvpx, there is a possible information disclosure due to improper input validation. This could lead to
    remote information disclosure with no additional execution privileges needed. User interaction is needed
    for exploitation. Product: AndroidVersions: Android-10Android ID: A-80479354 (CVE-2019-9433)

  - In libvpx, there is a possible resource exhaustion due to improper input validation. This could lead to
    remote denial of service with no additional execution privileges needed. User interaction is needed for
    exploitation. Product: AndroidVersions: Android-10Android ID: A-132783254 (CVE-2019-9371)

  - In ParseContentEncodingEntry of mkvparser.cc, there is a possible double free due to a missing reset of a
    freed pointer. This could lead to remote code execution with no additional execution privileges needed.
    User interaction is needed for exploitation. Product: Android. Versions: Android-7.0 Android-7.1.1
    Android-7.1.2 Android-8.0 Android-8.1 Android-9. Android ID: A-127702368. (CVE-2019-2126)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0060");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libvpx packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2126");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'libvpx-1.7.0-8.el8',
    'libvpx-debuginfo-1.7.0-8.el8',
    'libvpx-debugsource-1.7.0-8.el8',
    'libvpx-devel-1.7.0-8.el8',
    'libvpx-utils-1.7.0-8.el8',
    'libvpx-utils-debuginfo-1.7.0-8.el8'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libvpx');
}
