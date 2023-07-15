#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0078. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167477);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/15");

  script_cve_id(
    "CVE-2020-8648",
    "CVE-2020-14305",
    "CVE-2021-3715",
    "CVE-2021-29154",
    "CVE-2022-0492"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2022-0078)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - An out-of-bounds memory write flaw was found in how the Linux kernel's Voice Over IP H.323 connection
    tracking functionality handled connections on ipv6 port 1720. This flaw allows an unauthenticated remote
    user to crash the system, causing a denial of service. The highest threat from this vulnerability is to
    confidentiality, integrity, as well as system availability. (CVE-2020-14305)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the n_tty_receive_buf_common
    function in drivers/tty/n_tty.c. (CVE-2020-8648)

  - BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements,
    allowing them to execute arbitrary code within the kernel context. This affects
    arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c. (CVE-2021-29154)

  - A flaw was found in the Routing decision classifier in the Linux kernel's Traffic Control networking
    subsystem in the way it handled changing of classification filters, leading to a use-after-free condition.
    This flaw allows unprivileged local users to escalate their privileges on the system. The highest threat
    from this vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2021-3715)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0078");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14305");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-8648");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-29154");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3715");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-0492");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/06");
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
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-core-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.57.1044.gba9071a.lite'
  ],
  'CGSL MAIN 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.55.1133.g3e8f9d6'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
