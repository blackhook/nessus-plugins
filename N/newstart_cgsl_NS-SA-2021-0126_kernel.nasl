#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0126. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154593);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-19767", "CVE-2020-14351", "CVE-2020-25705");
  script_xref(name:"CEA-ID", value:"CEA-2020-0138");

  script_name(english:"NewStart CGSL MAIN 6.02 : kernel Multiple Vulnerabilities (NS-SA-2021-0126)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has kernel packages installed that are affected by multiple
vulnerabilities:

  - The Linux kernel before 5.4.2 mishandles ext4_expand_extra_isize, as demonstrated by use-after-free errors
    in __ext4_expand_extra_isize and ext4_xattr_set_entry, related to fs/ext4/inode.c and fs/ext4/super.c, aka
    CID-4ea99936a163. (CVE-2019-19767)

  - A flaw was found in the Linux kernel. A use-after-free memory flaw was found in the perf subsystem
    allowing a local attacker with permission to monitor perf events to corrupt memory and possibly escalate
    privileges. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2020-14351)

  - A flaw in ICMP packets in the Linux kernel may allow an attacker to quickly scan open UDP ports. This flaw
    allows an off-path remote attacker to effectively bypass source port UDP randomization. Software that
    relies on UDP source port randomization are indirectly affected as well on the Linux Based Products
    (RUGGEDCOM RM1224: All versions between v5.0 and v6.4, SCALANCE M-800: All versions between v5.0 and v6.4,
    SCALANCE S615: All versions between v5.0 and v6.4, SCALANCE SC-600: All versions prior to v2.1.3, SCALANCE
    W1750D: v8.3.0.1, v8.6.0, and v8.7.0, SIMATIC Cloud Connect 7: All versions, SIMATIC MV500 Family: All
    versions, SIMATIC NET CP 1243-1 (incl. SIPLUS variants): Versions 3.1.39 and later, SIMATIC NET CP 1243-7
    LTE EU: Version (CVE-2020-25705)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0126");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-19767");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14351");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-25705");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25705");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14351");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-ipaclones-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-sign-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'bpftool-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'bpftool-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-abi-whitelists-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-core-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-cross-headers-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-debug-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-debug-core-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-debug-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-debug-devel-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-debug-modules-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-debug-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-debug-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-debuginfo-common-x86_64-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-devel-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-headers-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-ipaclones-internal-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-modules-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-selftests-internal-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-sign-keys-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-tools-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-tools-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-tools-libs-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'kernel-tools-libs-devel-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'perf-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'python3-perf-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f',
    'python3-perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.19.376.gb6156ee3f'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
