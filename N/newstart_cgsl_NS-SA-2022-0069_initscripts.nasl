##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0069. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160781);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2008-3524");

  script_name(english:"NewStart CGSL MAIN 6.02 : initscripts Vulnerability (NS-SA-2022-0069)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has initscripts packages installed that are affected by a
vulnerability:

  - rc.sysinit in initscripts before 8.76.3-1 on Fedora 9 and other Linux platforms allows local users to
    delete arbitrary files via a symlink attack on a file or directory under (1) /var/lock or (2) /var/run.
    (CVE-2008-3524)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0069");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2008-3524");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL initscripts packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3524");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:initscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:netconsole-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:network-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:readonly-root");
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
    'initscripts-10.00.6-1.el8_2.1.cgslv6_2.1.g53c6791',
    'netconsole-service-10.00.6-1.el8_2.1.cgslv6_2.1.g53c6791',
    'network-scripts-10.00.6-1.el8_2.1.cgslv6_2.1.g53c6791',
    'readonly-root-10.00.6-1.el8_2.1.cgslv6_2.1.g53c6791'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'initscripts');
}
