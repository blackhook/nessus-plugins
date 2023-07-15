##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0040. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160815);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2017-18595",
    "CVE-2019-20934",
    "CVE-2020-11668",
    "CVE-2020-28374",
    "CVE-2021-3612",
    "CVE-2021-33033",
    "CVE-2021-33034",
    "CVE-2021-33909"
  );
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : kernel Multiple Vulnerabilities (NS-SA-2022-0040)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has kernel packages installed that are affected by
multiple vulnerabilities:

  - An issue was discovered in the Linux kernel before 4.14.11. A double free may be caused by the function
    allocate_trace_buffer in the file kernel/trace/trace.c. (CVE-2017-18595)

  - An issue was discovered in the Linux kernel before 5.2.6. On NUMA systems, the Linux fair scheduler has a
    use-after-free in show_numa_stats() because NUMA fault statistics are inappropriately freed, aka
    CID-16d51a590a8c. (CVE-2019-20934)

  - In the Linux kernel before 5.6.1, drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink camera USB
    driver) mishandles invalid descriptors, aka CID-a246b4d54770. (CVE-2020-11668)

  - In drivers/target/target_core_xcopy.c in the Linux kernel before 5.10.7, insufficient identifier checking
    in the LIO SCSI target code can be used by remote attackers to read or write files via directory traversal
    in an XCOPY request, aka CID-2896c93811e3. For example, an attack can occur over a network if the attacker
    has access to one iSCSI LUN. The attacker gains control over file access because I/O operations are
    proxied via an attacker-selected backstore. (CVE-2020-28374)

  - The Linux kernel before 5.11.14 has a use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c because
    the CIPSO and CALIPSO refcounting for the DOI definitions is mishandled, aka CID-ad5d07f4a9cd. This leads
    to writing an arbitrary value. (CVE-2021-33033)

  - In the Linux kernel before 5.12.4, net/bluetooth/hci_event.c has a use-after-free when destroying an
    hci_chan, aka CID-5c4c8c954409. This leads to writing an arbitrary value. (CVE-2021-33034)

  - fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer
    allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an
    unprivileged user, aka CID-8cae8cd89f05. (CVE-2021-33909)

  - An out-of-bounds memory write flaw was found in the Linux kernel's joystick devices subsystem in versions
    before 5.9-rc1, in the way the user calls ioctl JSIOCSBTNMAP. This flaw allows a local user to crash the
    system or possibly escalate their privileges on the system. The highest threat from this vulnerability is
    to confidentiality, integrity, as well as system availability. (CVE-2021-3612)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0040");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-18595");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-20934");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-11668");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-28374");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-33033");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-33034");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-33909");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3612");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3612");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-28374");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:bpftool");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_core:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
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
  script_set_attribute(attribute:"stig_severity", value:"II");
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
    'bpftool-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-abi-whitelists-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-core-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-debug-core-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-debug-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-debug-modules-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-modules-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'perf-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'python-perf-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite',
    'python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.318.g3b87fe1.lite'
  ],
  'CGSL MAIN 5.05': [
    'bpftool-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-abi-whitelists-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-debug-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-debug-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'perf-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'python-perf-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d',
    'python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.382.g95b322d'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
