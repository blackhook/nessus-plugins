##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0060. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160807);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2020-0543",
    "CVE-2020-0548",
    "CVE-2020-0549",
    "CVE-2020-8695",
    "CVE-2020-8696",
    "CVE-2020-8698",
    "CVE-2020-24489",
    "CVE-2020-24511",
    "CVE-2020-24512",
    "CVE-2020-24513"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : microcode_ctl Multiple Vulnerabilities (NS-SA-2022-0060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has microcode_ctl packages installed that are affected by
multiple vulnerabilities:

  - Incomplete cleanup from specific special register read operations in some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2020-0543)

  - Cleanup errors in some Intel(R) Processors may allow an authenticated user to potentially enable
    information disclosure via local access. (CVE-2020-0548)

  - Cleanup errors in some data cache evictions for some Intel(R) Processors may allow an authenticated user
    to potentially enable information disclosure via local access. (CVE-2020-0549)

  - Incomplete cleanup in some Intel(R) VT-d products may allow an authenticated user to potentially enable
    escalation of privilege via local access. (CVE-2020-24489)

  - Improper isolation of shared resources in some Intel(R) Processors may allow an authenticated user to
    potentially enable information disclosure via local access. (CVE-2020-24511, CVE-2020-8698)

  - Observable timing discrepancy in some Intel(R) Processors may allow an authenticated user to potentially
    enable information disclosure via local access. (CVE-2020-24512)

  - Domain-bypass transient execution vulnerability in some Intel Atom(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2020-24513)

  - Observable discrepancy in the RAPL interface for some Intel(R) Processors may allow a privileged user to
    potentially enable information disclosure via local access. (CVE-2020-8695)

  - Improper removal of sensitive information before storage or transfer in some Intel(R) Processors may allow
    an authenticated user to potentially enable information disclosure via local access. (CVE-2020-8696)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0060");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-0543");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-0548");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-0549");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-24489");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-24511");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-24512");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-24513");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8695");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8696");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8698");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL microcode_ctl packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24489");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:microcode_ctl");
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

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'microcode_ctl-20210216-1.20210608.1.el8_4'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'microcode_ctl');
}
