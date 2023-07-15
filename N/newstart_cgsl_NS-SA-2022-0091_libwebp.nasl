#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0091. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167502);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

  script_cve_id(
    "CVE-2018-25009",
    "CVE-2018-25010",
    "CVE-2018-25012",
    "CVE-2018-25013",
    "CVE-2018-25014",
    "CVE-2020-36330",
    "CVE-2020-36331",
    "CVE-2020-36332"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : libwebp Multiple Vulnerabilities (NS-SA-2022-0091)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has libwebp packages installed that are affected by multiple
vulnerabilities:

  - A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in GetLE16(). (CVE-2018-25009)

  - A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in ApplyFilter().
    (CVE-2018-25010)

  - A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in GetLE24(). (CVE-2018-25012)

  - A heap-based buffer overflow was found in libwebp in versions before 1.0.1 in ShiftBytes().
    (CVE-2018-25013)

  - A use of uninitialized value was found in libwebp in versions before 1.0.1 in ReadSymbol().
    (CVE-2018-25014)

  - A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function
    ChunkVerifyAndAssign. The highest threat from this vulnerability is to data confidentiality and to the
    service availability. (CVE-2020-36330)

  - A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function
    ChunkAssignData. The highest threat from this vulnerability is to data confidentiality and to the service
    availability. (CVE-2020-36331)

  - A flaw was found in libwebp in versions before 1.0.1. When reading a file libwebp allocates an excessive
    amount of memory. The highest threat from this vulnerability is to the service availability.
    (CVE-2020-36332)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0091");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-25009");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-25010");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-25012");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-25013");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-25014");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-36330");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-36331");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-36332");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libwebp packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-25014");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwebp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'libwebp-1.0.0-5.el8'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libwebp');
}
