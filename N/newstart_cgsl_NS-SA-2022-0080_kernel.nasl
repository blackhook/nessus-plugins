#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0080. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167485);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

  script_cve_id("CVE-2020-25704");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Vulnerability (NS-SA-2022-0080)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
a vulnerability:

  - A flaw memory leak in the Linux kernel performance monitoring subsystem was found in the way if using
    PERF_EVENT_IOC_SET_FILTER. A local user could use this flaw to starve the resources causing denial of
    service. (CVE-2020-25704)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0080");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25704");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25704");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-sign-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-sign-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-perf-debuginfo");
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
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-core-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1048.g0e38301.lite'
  ],
  'CGSL MAIN 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1138.g2d3104c'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
