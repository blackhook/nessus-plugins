#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0021. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174097);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2018-5818", "CVE-2018-5819", "CVE-2019-3820");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : xchat Multiple Vulnerabilities (NS-SA-2023-0021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has xchat packages installed that are affected by
multiple vulnerabilities:

  - An error within the parse_rollei() function (internal/dcraw_common.cpp) within LibRaw versions prior to
    0.19.1 can be exploited to trigger an infinite loop. (CVE-2018-5818)

  - An error within the parse_sinar_ia() function (internal/dcraw_common.cpp) within LibRaw versions prior
    to 0.19.1 can be exploited to exhaust available CPU resources. (CVE-2018-5819)

  - It was discovered that the gnome-shell lock screen since version 3.15.91 did not properly restrict all
    contextual actions. An attacker with physical access to a locked workstation could invoke certain keyboard
    shortcuts, and potentially other actions. (CVE-2019-3820)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0021");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-5818");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-5819");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-3820");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL xchat packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3820");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:xchat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:xchat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:xchat-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:xchat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:xchat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:xchat-tcl");
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

if (os_release !~ "CGSL CORE 5.05" &&
    os_release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.05': [
    'xchat-2.8.8-25.el7',
    'xchat-debuginfo-2.8.8-25.el7',
    'xchat-tcl-2.8.8-25.el7'
  ],
  'CGSL MAIN 5.05': [
    'xchat-2.8.8-25.el7',
    'xchat-debuginfo-2.8.8-25.el7',
    'xchat-tcl-2.8.8-25.el7'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xchat');
}
