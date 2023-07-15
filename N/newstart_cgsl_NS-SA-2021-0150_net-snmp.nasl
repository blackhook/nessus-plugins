#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0150. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154487);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/27");

  script_cve_id("CVE-2020-15862");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : net-snmp Vulnerability (NS-SA-2021-0150)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has net-snmp packages installed that are affected
by a vulnerability:

  - Net-SNMP through 5.7.3 has Improper Privilege Management because SNMP WRITE access to the EXTEND MIB
    provides the ability to run arbitrary commands as root. (CVE-2020-15862)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0150");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-15862");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL net-snmp packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15862");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:net-snmp-agent-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:net-snmp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:net-snmp-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:net-snmp-agent-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:net-snmp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:net-snmp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:net-snmp-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:net-snmp-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:net-snmp-utils");
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
    'net-snmp-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-agent-libs-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-devel-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-gui-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-libs-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-perl-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-python-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-sysvinit-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-utils-5.7.2-49.el7_9.1.cgslv5_5'
  ],
  'CGSL MAIN 5.05': [
    'net-snmp-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-agent-libs-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-devel-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-gui-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-libs-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-perl-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-python-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-sysvinit-5.7.2-49.el7_9.1.cgslv5_5',
    'net-snmp-utils-5.7.2-49.el7_9.1.cgslv5_5'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'net-snmp');
}
