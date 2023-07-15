##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0073. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143889);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/10");

  script_cve_id("CVE-2019-19768", "CVE-2020-10711");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2020-0073)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - In the Linux kernel 5.4.0-rc2, there is a use-after-free (read) in the __blk_add_trace function in
    kernel/trace/blktrace.c (which is used to fill out a blk_io_trace structure and place it in a per-cpu sub-
    buffer). (CVE-2019-19768)

  - A NULL pointer dereference flaw was found in the Linux kernel's SELinux subsystem in versions before 5.7.
    This flaw occurs while importing the Commercial IP Security Option (CIPSO) protocol's category bitmap into
    the SELinux extensible bitmap via the' ebitmap_netlbl_import' routine. While processing the CIPSO
    restricted bitmap tag in the 'cipso_v4_parsetag_rbm' routine, it sets the security attribute to indicate
    that the category bitmap is present, even if it has not been allocated. This issue leads to a NULL pointer
    dereference issue while importing the same category bitmap into SELinux. This flaw allows a remote network
    user to crash the system kernel, resulting in a denial of service. (CVE-2020-10711)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0073");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19768");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-core-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.47.655.gf6ce0e6.lite'
  ],
  'CGSL MAIN 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.45.762.gcf9329a'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
