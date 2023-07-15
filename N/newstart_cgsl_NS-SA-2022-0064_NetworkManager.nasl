##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0064. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160796);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-20297");

  script_name(english:"NewStart CGSL MAIN 6.02 : NetworkManager Vulnerability (NS-SA-2022-0064)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has NetworkManager packages installed that are affected by a
vulnerability:

  - A flaw was found in NetworkManager in versions before 1.30.0. Setting match.path and activating a profile
    crashes NetworkManager. The highest threat from this vulnerability is to system availability.
    (CVE-2021-20297)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0064");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-20297");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL NetworkManager packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20297");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-adsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-adsl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-bluetooth-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-cloud-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-cloud-setup-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-config-connectivity-redhat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-config-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-dispatcher-routing-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-libnm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-libnm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-libnm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-ovs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-ppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-ppp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-team");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-team-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-tui-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-wifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-wifi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-wwan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:NetworkManager-wwan-debuginfo");
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
    'NetworkManager-1.30.0-9.el8_4',
    'NetworkManager-adsl-1.30.0-9.el8_4',
    'NetworkManager-adsl-debuginfo-1.30.0-9.el8_4',
    'NetworkManager-bluetooth-1.30.0-9.el8_4',
    'NetworkManager-bluetooth-debuginfo-1.30.0-9.el8_4',
    'NetworkManager-cloud-setup-1.30.0-9.el8_4',
    'NetworkManager-cloud-setup-debuginfo-1.30.0-9.el8_4',
    'NetworkManager-config-connectivity-redhat-1.30.0-9.el8_4',
    'NetworkManager-config-server-1.30.0-9.el8_4',
    'NetworkManager-debuginfo-1.30.0-9.el8_4',
    'NetworkManager-debugsource-1.30.0-9.el8_4',
    'NetworkManager-dispatcher-routing-rules-1.30.0-9.el8_4',
    'NetworkManager-libnm-1.30.0-9.el8_4',
    'NetworkManager-libnm-debuginfo-1.30.0-9.el8_4',
    'NetworkManager-libnm-devel-1.30.0-9.el8_4',
    'NetworkManager-ovs-1.30.0-9.el8_4',
    'NetworkManager-ovs-debuginfo-1.30.0-9.el8_4',
    'NetworkManager-ppp-1.30.0-9.el8_4',
    'NetworkManager-ppp-debuginfo-1.30.0-9.el8_4',
    'NetworkManager-team-1.30.0-9.el8_4',
    'NetworkManager-team-debuginfo-1.30.0-9.el8_4',
    'NetworkManager-tui-1.30.0-9.el8_4',
    'NetworkManager-tui-debuginfo-1.30.0-9.el8_4',
    'NetworkManager-wifi-1.30.0-9.el8_4',
    'NetworkManager-wifi-debuginfo-1.30.0-9.el8_4',
    'NetworkManager-wwan-1.30.0-9.el8_4',
    'NetworkManager-wwan-debuginfo-1.30.0-9.el8_4'
  ]
};
var pkg_list = pkgs[release];

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'NetworkManager');
}
