#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0034. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149338);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_cve_id("CVE-2020-11078");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : resource-agents Vulnerability (NS-SA-2021-0034)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has resource-agents packages installed that are
affected by a vulnerability:

  - In httplib2 before version 0.18.0, an attacker controlling unescaped part of uri for
    `httplib2.Http.request()` could change request headers and body, send additional hidden requests to same
    server. This vulnerability impacts software that uses httplib2 with uri constructed by string
    concatenation, as opposed to proper urllib building with escaping. This has been fixed in 0.18.0.
    (CVE-2020-11078)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0034");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL resource-agents packages. Note that updated packages may not be available yet. Please
contact ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11078");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'resource-agents-4.1.1-61.el7_9.4',
    'resource-agents-aliyun-4.1.1-61.el7_9.4',
    'resource-agents-gcp-4.1.1-61.el7_9.4',
    'resource-agents-sap-4.1.1-61.el7_9.4',
    'resource-agents-sap-hana-4.1.1-61.el7_9.4',
    'resource-agents-sap-hana-scaleout-0.164.0-6.el7_9.4',
    'sap-cluster-connector-3.0.1-37.el7_9.4'
  ],
  'CGSL MAIN 5.04': [
    'resource-agents-4.1.1-61.el7_9.4',
    'resource-agents-aliyun-4.1.1-61.el7_9.4',
    'resource-agents-gcp-4.1.1-61.el7_9.4',
    'resource-agents-sap-4.1.1-61.el7_9.4',
    'resource-agents-sap-hana-4.1.1-61.el7_9.4',
    'resource-agents-sap-hana-scaleout-0.164.0-6.el7_9.4',
    'sap-cluster-connector-3.0.1-37.el7_9.4'
  ]
};
pkg_list = pkgs[release];

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'resource-agents');
}
