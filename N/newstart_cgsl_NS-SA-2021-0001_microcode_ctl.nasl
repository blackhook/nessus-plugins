##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0001. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147405);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/11");

  script_cve_id(
    "CVE-2019-0117",
    "CVE-2020-0543",
    "CVE-2020-0548",
    "CVE-2020-0549",
    "CVE-2020-8696",
    "CVE-2020-8698"
  );

  script_name(english:"NewStart CGSL MAIN 4.06 : microcode_ctl Multiple Vulnerabilities (NS-SA-2021-0001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.06, has microcode_ctl packages installed that are affected by
multiple vulnerabilities:

  - Insufficient access control in protected memory subsystem for Intel(R) SGX for 6th, 7th, 8th, 9th
    Generation Intel(R) Core(TM) Processor Families; Intel(R) Xeon(R) Processor E3-1500 v5, v6 Families;
    Intel(R) Xeon(R) E-2100 & E-2200 Processor Families with Intel(R) Processor Graphics may allow a
    privileged user to potentially enable information disclosure via local access. (CVE-2019-0117)

  - Cleanup errors in some Intel(R) Processors may allow an authenticated user to potentially enable
    information disclosure via local access. (CVE-2020-0548)

  - Cleanup errors in some data cache evictions for some Intel(R) Processors may allow an authenticated user
    to potentially enable information disclosure via local access. (CVE-2020-0549)

  - Improper removal of sensitive information before storage or transfer in some Intel(R) Processors may allow
    an authenticated user to potentially enable information disclosure via local access. (CVE-2020-8696)

  - Improper isolation of shared resources in some Intel(R) Processors may allow an authenticated user to
    potentially enable information disclosure via local access. (CVE-2020-8698)

  - Incomplete cleanup from specific special register read operations in some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2020-0543)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0001");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL microcode_ctl packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8698");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
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

if (release !~ "CGSL MAIN 4.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.06');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 4.06': [
    'microcode_ctl-1.17-33.31.el6_10'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'microcode_ctl');
}
