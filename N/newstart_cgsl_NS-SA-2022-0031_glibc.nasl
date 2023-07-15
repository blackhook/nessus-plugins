##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0031. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160802);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2014-4043", "CVE-2018-20796");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : glibc Multiple Vulnerabilities (NS-SA-2022-0031)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has glibc packages installed that are affected by
multiple vulnerabilities:

  - The posix_spawn_file_actions_addopen function in glibc before 2.20 does not copy its path argument in
    accordance with the POSIX specification, which allows context-dependent attackers to trigger use-after-
    free vulnerabilities. (CVE-2014-4043)

  - In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has
    Uncontrolled Recursion, as demonstrated by '(\227|)(\\1\\1|t1|\\\2537)+' in grep. (CVE-2018-20796)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0031");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2014-4043");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-20796");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL glibc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4043");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-20796");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
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
    'glibc-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-common-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-debuginfo-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-debuginfo-common-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-devel-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-headers-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-i18n-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-iconv-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-lang-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-locale-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-static-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-tools-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'glibc-utils-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite',
    'nscd-2.17-322.el7_9.cgslv5_5.0.8.g351078a.lite'
  ],
  'CGSL MAIN 5.05': [
    'glibc-2.17-322.el7_9.cgslv5_5.0.3.ged42fc3',
    'glibc-common-2.17-322.el7_9.cgslv5_5.0.3.ged42fc3',
    'glibc-debuginfo-2.17-322.el7_9.cgslv5_5.0.3.ged42fc3',
    'glibc-debuginfo-common-2.17-322.el7_9.cgslv5_5.0.3.ged42fc3',
    'glibc-devel-2.17-322.el7_9.cgslv5_5.0.3.ged42fc3',
    'glibc-headers-2.17-322.el7_9.cgslv5_5.0.3.ged42fc3',
    'glibc-static-2.17-322.el7_9.cgslv5_5.0.3.ged42fc3',
    'glibc-utils-2.17-322.el7_9.cgslv5_5.0.3.ged42fc3',
    'nscd-2.17-322.el7_9.cgslv5_5.0.3.ged42fc3'
  ]
};
var pkg_list = pkgs[release];

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc');
}
