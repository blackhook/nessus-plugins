##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0021. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160792);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-41159", "CVE-2021-41160");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : freerdp Multiple Vulnerabilities (NS-SA-2022-0021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has freerdp packages installed that are affected
by multiple vulnerabilities:

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    All FreeRDP clients prior to version 2.4.1 using gateway connections (`/gt:rpc`) fail to validate input
    data. A malicious gateway might allow client memory to be written out of bounds. This issue has been
    resolved in version 2.4.1. If you are unable to update then use `/gt:http` rather than /gt:rdp connections
    if possible or use a direct connection without a gateway. (CVE-2021-41159)

  - FreeRDP is a free implementation of the Remote Desktop Protocol (RDP), released under the Apache license.
    In affected versions a malicious server might trigger out of bound writes in a connected client.
    Connections using GDI or SurfaceCommands to send graphics updates to the client might send `0`
    width/height or out of bound rectangles to trigger out of bound writes. With `0` width or heigth the
    memory allocation will be `0` but the missing bounds checks allow writing to the pointer at this (not
    allocated) region. This issue has been patched in FreeRDP 2.4.1. (CVE-2021-41160)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0021");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-41159");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-41160");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL freerdp packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41160");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:libwinpr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:libwinpr-devel");
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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL CORE 5.04': [
    'freerdp-2.1.1-5.el7_9',
    'freerdp-debuginfo-2.1.1-5.el7_9',
    'freerdp-devel-2.1.1-5.el7_9',
    'freerdp-libs-2.1.1-5.el7_9',
    'libwinpr-2.1.1-5.el7_9',
    'libwinpr-devel-2.1.1-5.el7_9'
  ],
  'CGSL MAIN 5.04': [
    'freerdp-2.1.1-5.el7_9',
    'freerdp-debuginfo-2.1.1-5.el7_9',
    'freerdp-devel-2.1.1-5.el7_9',
    'freerdp-libs-2.1.1-5.el7_9',
    'libwinpr-2.1.1-5.el7_9',
    'libwinpr-devel-2.1.1-5.el7_9'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp');
}
