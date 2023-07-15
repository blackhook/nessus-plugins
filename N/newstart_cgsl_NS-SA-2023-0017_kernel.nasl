#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0017. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174091);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id(
    "CVE-2020-14386",
    "CVE-2021-3715",
    "CVE-2021-22543",
    "CVE-2021-22555",
    "CVE-2021-32399",
    "CVE-2021-37576",
    "CVE-2022-0330",
    "CVE-2022-0492",
    "CVE-2022-1011",
    "CVE-2022-1016",
    "CVE-2022-2639",
    "CVE-2022-3542",
    "CVE-2022-3586",
    "CVE-2022-3594",
    "CVE-2022-32250",
    "CVE-2022-40768",
    "CVE-2022-41218",
    "CVE-2022-41850",
    "CVE-2022-43750"
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : kernel Multiple Vulnerabilities (NS-SA-2023-0017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has kernel packages installed that are affected by
multiple vulnerabilities:

  - A flaw was found in the Linux kernel before 5.9-rc4. Memory corruption can be exploited to gain root
    privileges from unprivileged processes. The highest threat from this vulnerability is to data
    confidentiality and integrity. (CVE-2020-14386)

  - An issue was discovered in Linux: KVM through Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass
    RO checks and can lead to pages being freed while still accessible by the VMM and guest. This allows users
    with the ability to start and control a VM to read/write random pages of memory and can result in local
    privilege escalation. (CVE-2021-22543)

  - A heap out-of-bounds write affecting Linux since v2.6.19-rc1 was discovered in net/netfilter/x_tables.c.
    This allows an attacker to gain privileges or cause a DoS (via heap memory corruption) through user name
    space (CVE-2021-22555)

  - net/bluetooth/hci_request.c in the Linux kernel through 5.12.2 has a race condition for removal of the HCI
    controller. (CVE-2021-32399)

  - A flaw was found in the Routing decision classifier in the Linux kernel's Traffic Control networking
    subsystem in the way it handled changing of classification filters, leading to a use-after-free condition.
    This flaw allows unprivileged local users to escalate their privileges on the system. The highest threat
    from this vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2021-3715)

  - arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest
    OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e. (CVE-2021-37576)

  - A random memory access flaw was found in the Linux kernel's GPU i915 kernel driver functionality in the
    way a user may run malicious code on the GPU. This flaw allows a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-0330)

  - A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the
    kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups
    v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.
    (CVE-2022-0492)

  - A use-after-free flaw was found in the Linux kernel's FUSE filesystem in the way a user triggers write().
    This flaw allows a local user to gain unauthorized access to data from the FUSE filesystem, resulting in
    privilege escalation. (CVE-2022-1011)

  - A flaw was found in the Linux kernel in net/netfilter/nf_tables_core.c:nft_do_chain, which can cause a
    use-after-free. This issue needs to handle 'return' with proper preconditions, as it can lead to a kernel
    information leak problem caused by a local, unprivileged attacker. (CVE-2022-1016)

  - An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of
    actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size()
    function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This
    flaw allows a local user to crash or potentially escalate their privileges on the system. (CVE-2022-2639)

  - net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create
    user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to
    a use-after-free. (CVE-2022-32250)

  - A flaw was found in the Linux kernel's networking code. A use-after-free was found in the way the sch_sfb
    enqueue function used the socket buffer (SKB) cb field after the same SKB had been enqueued (and freed)
    into a child qdisc. This flaw allows a local, unprivileged user to crash the system, causing a denial of
    service. (CVE-2022-3586)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The
    manipulation leads to logging of excessive data. The attack can be launched remotely. It is recommended to
    apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211363.
    (CVE-2022-3594)

  - drivers/scsi/stex.c in the Linux kernel through 5.19.9 allows local users to obtain sensitive information
    from kernel memory because stex_queuecommand_lck lacks a memset for the PASSTHRU_CMD case.
    (CVE-2022-40768)

  - In drivers/media/dvb-core/dmxdev.c in the Linux kernel through 5.19.10, there is a use-after-free caused
    by refcount races, affecting dvb_demux_open and dvb_dmxdev_release. (CVE-2022-41218)

  - roccat_report_event in drivers/hid/hid-roccat.c in the Linux kernel through 5.19.12 has a race condition
    and resultant use-after-free in certain situations where a report is received while copying a
    report->value is in progress. (CVE-2022-41850)

  - drivers/usb/mon/mon_bin.c in usbmon in the Linux kernel before 5.19.15 and 6.x before 6.0.1 allows a user-
    space client to corrupt the monitor's internal memory. (CVE-2022-43750)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0017");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-14386");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-22543");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-22555");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-32399");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-3715");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-37576");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-0330");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-0492");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-1011");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-2639");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-32250");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-3542");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-3586");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-3594");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-40768");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-41218");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-41850");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-43750");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32250");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Netfilter x_tables Heap OOB Write Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

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
    'bpftool-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-abi-whitelists-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-core-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-debug-core-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-debug-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-debug-modules-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-modules-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'perf-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'python-perf-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite',
    'python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.19.328.g4e62c58.lite'
  ],
  'CGSL MAIN 5.05': [
    'bpftool-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-abi-whitelists-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-debug-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-debug-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-debug-devel-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-debuginfo-common-x86_64-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-devel-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-headers-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-tools-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-tools-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-tools-libs-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'kernel-tools-libs-devel-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'perf-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'python-perf-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493',
    'python-perf-debuginfo-3.10.0-957.27.2.el7.cgslv5_5.20.421.gee22493'
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
