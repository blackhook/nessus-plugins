#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0030. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174089);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2022-3821");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : systemd Vulnerability (NS-SA-2023-0030)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has systemd packages installed that are affected
by a vulnerability:

  - An off-by-one Error issue was discovered in Systemd in format_timespan() function of time-util.c. An
    attacker could supply specific values for time and accuracy that leads to buffer overrun in
    format_timespan(), leading to a Denial of Service. (CVE-2022-3821)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0030");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-3821");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL systemd packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3821");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_core:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL CORE 5.04" &&
    os_release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'libgudev1-219-67.el7.cgslv5.0.27.gf7f3d79.lite',
    'libgudev1-devel-219-67.el7.cgslv5.0.27.gf7f3d79.lite',
    'systemd-219-67.el7.cgslv5.0.27.gf7f3d79.lite',
    'systemd-debuginfo-219-67.el7.cgslv5.0.27.gf7f3d79.lite',
    'systemd-devel-219-67.el7.cgslv5.0.27.gf7f3d79.lite',
    'systemd-journal-gateway-219-67.el7.cgslv5.0.27.gf7f3d79.lite',
    'systemd-libs-219-67.el7.cgslv5.0.27.gf7f3d79.lite',
    'systemd-networkd-219-67.el7.cgslv5.0.27.gf7f3d79.lite',
    'systemd-python-219-67.el7.cgslv5.0.27.gf7f3d79.lite',
    'systemd-resolved-219-67.el7.cgslv5.0.27.gf7f3d79.lite',
    'systemd-sysv-219-67.el7.cgslv5.0.27.gf7f3d79.lite'
  ],
  'CGSL MAIN 5.04': [
    'libgudev1-219-67.el7.cgslv5.0.24.g2338980',
    'libgudev1-devel-219-67.el7.cgslv5.0.24.g2338980',
    'systemd-219-67.el7.cgslv5.0.24.g2338980',
    'systemd-debuginfo-219-67.el7.cgslv5.0.24.g2338980',
    'systemd-devel-219-67.el7.cgslv5.0.24.g2338980',
    'systemd-journal-gateway-219-67.el7.cgslv5.0.24.g2338980',
    'systemd-libs-219-67.el7.cgslv5.0.24.g2338980',
    'systemd-networkd-219-67.el7.cgslv5.0.24.g2338980',
    'systemd-python-219-67.el7.cgslv5.0.24.g2338980',
    'systemd-resolved-219-67.el7.cgslv5.0.24.g2338980',
    'systemd-sysv-219-67.el7.cgslv5.0.24.g2338980'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'systemd');
}
