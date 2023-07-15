#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-1062.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109113);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2016-3672",
    "CVE-2016-7913",
    "CVE-2016-8633",
    "CVE-2017-7294",
    "CVE-2017-8824",
    "CVE-2017-9725",
    "CVE-2017-12154",
    "CVE-2017-12190",
    "CVE-2017-13166",
    "CVE-2017-13305",
    "CVE-2017-14140",
    "CVE-2017-15116",
    "CVE-2017-15121",
    "CVE-2017-15126",
    "CVE-2017-15127",
    "CVE-2017-15129",
    "CVE-2017-15265",
    "CVE-2017-15274",
    "CVE-2017-17448",
    "CVE-2017-17449",
    "CVE-2017-17558",
    "CVE-2017-18017",
    "CVE-2017-18203",
    "CVE-2017-18270",
    "CVE-2017-1000252",
    "CVE-2017-1000407",
    "CVE-2017-1000410",
    "CVE-2018-5750",
    "CVE-2018-6927",
    "CVE-2018-1000004"
  );
  script_xref(name:"RHSA", value:"2018:1062");

  script_name(english:"Oracle Linux 7 : kernel (ELSA-2018-1062)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2018-1062 advisory.

  - drivers/firewire/net.c in the Linux kernel before 4.8.7, in certain unusual hardware configurations,
    allows remote attackers to execute arbitrary code via crafted fragmented packets. (CVE-2016-8633)

  - The arch_pick_mmap_layout function in arch/x86/mm/mmap.c in the Linux kernel through 4.5.2 does not
    properly randomize the legacy base address, which makes it easier for local users to defeat the intended
    restrictions on the ADDR_NO_RANDOMIZE flag, and bypass the ASLR protection mechanism for a setuid or
    setgid program, by disabling stack-consumption resource limits. (CVE-2016-3672)

  - The prepare_vmcs02 function in arch/x86/kvm/vmx.c in the Linux kernel through 4.13.3 does not ensure that
    the CR8-load exiting and CR8-store exiting L0 vmcs02 controls exist in cases where L1 omits the use
    TPR shadow vmcs12 control, which allows KVM L2 guest OS users to obtain read and write access to the
    hardware CR8 register. (CVE-2017-12154)

  - The bio_map_user_iov and bio_unmap_user functions in block/bio.c in the Linux kernel before 4.13.8 do
    unbalanced refcounting when a SCSI I/O vector has small consecutive buffers belonging to the same page.
    The bio_add_pc_page function merges them into one, but the page reference is never dropped. This causes a
    memory leak and possible system lockup (exploitable against the host OS by a guest OS user, if a SCSI disk
    is passed through to a virtual machine) due to an out-of-memory condition. (CVE-2017-12190)

  - The Linux Kernel 2.6.32 and later are affected by a denial of service, by flooding the diagnostic port
    0x80 an exception can be triggered leading to a kernel panic. (CVE-2017-1000407)

  - The dccp_disconnect function in net/dccp/proto.c in the Linux kernel through 4.14.3 allows local users to
    gain privileges or cause a denial of service (use-after-free) via an AF_UNSPEC connect system call during
    the DCCP_LISTEN state. (CVE-2017-8824)

  - The move_pages system call in mm/migrate.c in the Linux kernel before 4.12.9 doesn't check the effective
    uid of the target process, enabling a local attacker to learn the memory layout of a setuid executable
    despite ASLR. (CVE-2017-14140)

  - The vmw_surface_define_ioctl function in drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux kernel
    through 4.10.6 does not validate addition of certain levels data, which allows local users to trigger an
    integer overflow and out-of-bounds write, and cause a denial of service (system hang or crash) or possibly
    gain privileges, via a crafted ioctl call for a /dev/dri/renderD* device. (CVE-2017-7294)

  - In all Qualcomm products with Android releases from CAF using the Linux kernel, during DMA allocation, due
    to wrong data type of size, allocation size gets truncated which makes allocation succeed when it should
    fail. (CVE-2017-9725)

  - A flaw was found in the hugetlb_mcopy_atomic_pte function in mm/hugetlb.c in the Linux kernel before 4.13.
    A superfluous implicit page unlock for VM_SHARED hugetlbfs mapping could trigger a local denial of service
    (BUG). (CVE-2017-15127)

  - A use-after-free vulnerability was found in network namespaces code affecting the Linux kernel before
    4.14.11. The function get_net_ns_by_id() in net/core/net_namespace.c does not check for the net::count
    value after it has found a peer network in netns_ids idr, which could lead to double free and memory
    corruption. This vulnerability could allow an unprivileged local user to induce kernel memory corruption
    on the system, leading to a crash. Due to the nature of the flaw, privilege escalation cannot be fully
    ruled out, although it is thought to be unlikely. (CVE-2017-15129)

  - Race condition in the ALSA subsystem in the Linux kernel before 4.13.8 allows local users to cause a
    denial of service (use-after-free) or possibly have unspecified other impact via crafted /dev/snd/seq
    ioctl calls, related to sound/core/seq/seq_clientmgr.c and sound/core/seq/seq_ports.c. (CVE-2017-15265)

  - The __netlink_deliver_tap_skb function in net/netlink/af_netlink.c in the Linux kernel through 4.14.4,
    when CONFIG_NLMON is enabled, does not restrict observations of Netlink messages to a single net
    namespace, which allows local users to obtain sensitive information by leveraging the CAP_NET_ADMIN
    capability to sniff an nlmon interface for all Netlink activity on the system. (CVE-2017-17449)

  - The usb_destroy_configuration function in drivers/usb/core/config.c in the USB core subsystem in the Linux
    kernel through 4.14.5 does not consider the maximum number of configurations and interfaces before
    attempting to release resources, which allows local users to cause a denial of service (out-of-bounds
    write access) or possibly have unspecified other impact via a crafted USB device. (CVE-2017-17558)

  - The Linux kernel version 3.3-rc1 and later is affected by a vulnerability lies in the processing of
    incoming L2CAP commands - ConfigRequest, and ConfigResponse messages. This info leak is a result of
    uninitialized stack variables that may be returned to an attacker in their uninitialized state. By
    manipulating the code flows that precede the handling of these configuration messages, an attacker can
    also gain some control over which data will be held in the uninitialized stack variables. This can allow
    him to bypass KASLR, and stack canaries protection - as both pointers and stack canaries may be leaked in
    this manner. Combining this vulnerability (for example) with the previously disclosed RCE vulnerability in
    L2CAP configuration parsing (CVE-2017-1000251) may allow an attacker to exploit the RCE against kernels
    which were built with the above mitigations. These are the specifics of this vulnerability: In the
    function l2cap_parse_conf_rsp and in the function l2cap_parse_conf_req the following variable is declared
    without initialization: struct l2cap_conf_efs efs; In addition, when parsing input configuration
    parameters in both of these functions, the switch case for handling EFS elements may skip the memcpy call
    that will write to the efs variable: ... case L2CAP_CONF_EFS: if (olen == sizeof(efs)) memcpy(&efs;, (void
    *)val, olen); ... The olen in the above if is attacker controlled, and regardless of that if, in both of
    these functions the efs variable would eventually be added to the outgoing configuration request that is
    being built: l2cap_add_conf_opt(&ptr;, L2CAP_CONF_EFS, sizeof(efs), (unsigned long) &efs;); So by sending a
    configuration request, or response, that contains an L2CAP_CONF_EFS element, but with an element length
    that is not sizeof(efs) - the memcpy to the uninitialized efs variable can be avoided, and the
    uninitialized variable would be returned to the attacker (16 bytes). (CVE-2017-1000410)

  - The acpi_smbus_hc_add function in drivers/acpi/sbshc.c in the Linux kernel through 4.14.15 allows local
    users to obtain sensitive address information by reading dmesg data from an SBS HC printk call.
    (CVE-2018-5750)

  - The xc2028_set_config function in drivers/media/tuners/tuner-xc2028.c in the Linux kernel before 4.6
    allows local users to gain privileges or cause a denial of service (use-after-free) via vectors involving
    omission of the firmware name from a certain data structure. (CVE-2016-7913)

  - An elevation of privilege vulnerability in the kernel v4l2 video driver. Product: Android. Versions:
    Android kernel. Android ID A-34624167. (CVE-2017-13166)

  - The rngapi_reset function in crypto/rng.c in the Linux kernel before 4.2 allows attackers to cause a
    denial of service (NULL pointer dereference). (CVE-2017-15116)

  - A non-privileged user is able to mount a fuse filesystem on RHEL 6 or 7 and crash a system if an
    application punches a hole in a file that does not end aligned to a page boundary. (CVE-2017-15121)

  - A use-after-free flaw was found in fs/userfaultfd.c in the Linux kernel before 4.13.6. The issue is
    related to the handling of fork failure when dealing with event messages. Failure to fork correctly can
    lead to a situation where a fork event will be removed from an already freed list of events with
    userfaultfd_ctx_put(). (CVE-2017-15126)

  - net/netfilter/nfnetlink_cthelper.c in the Linux kernel through 4.14.4 does not require the CAP_NET_ADMIN
    capability for new, get, and del operations, which allows local users to bypass intended access
    restrictions because the nfnl_cthelper_list data structure is shared across all net namespaces.
    (CVE-2017-17448)

  - The tcpmss_mangle_packet function in net/netfilter/xt_TCPMSS.c in the Linux kernel before 4.11, and 4.9.x
    before 4.9.36, allows remote attackers to cause a denial of service (use-after-free and memory corruption)
    or possibly have unspecified other impact by leveraging the presence of xt_TCPMSS in an iptables action.
    (CVE-2017-18017)

  - The dm_get_from_kobject function in drivers/md/dm.c in the Linux kernel before 4.14.3 allow local users to
    cause a denial of service (BUG) by leveraging a race condition with __dm_destroy during creation and
    removal of DM devices. (CVE-2017-18203)

  - The KVM subsystem in the Linux kernel through 4.13.3 allows guest OS users to cause a denial of service
    (assertion failure, and hypervisor hang or crash) via an out-of bounds guest_irq value, related to
    arch/x86/kvm/vmx.c and virt/kvm/eventfd.c. (CVE-2017-1000252)

  - The futex_requeue function in kernel/futex.c in the Linux kernel before 4.14.15 might allow attackers to
    cause a denial of service (integer overflow) or possibly have unspecified other impact by triggering a
    negative wake or requeue value. (CVE-2018-6927)

  - In the Linux kernel 4.12, 3.10, 2.6 and possibly earlier versions a race condition vulnerability exists in
    the sound system, this can lead to a deadlock and denial of service condition. (CVE-2018-1000004)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-1062.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18017");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['3.10.0-862.el7'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-1062');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '3.10';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-3.10.0-862.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-3.10.0'},
    {'reference':'kernel-abi-whitelists-3.10.0-862.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-3.10.0'},
    {'reference':'kernel-debug-3.10.0-862.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-3.10.0'},
    {'reference':'kernel-debug-devel-3.10.0-862.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-3.10.0'},
    {'reference':'kernel-devel-3.10.0-862.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-3.10.0'},
    {'reference':'kernel-headers-3.10.0-862.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-3.10.0'},
    {'reference':'kernel-tools-3.10.0-862.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-3.10.0'},
    {'reference':'kernel-tools-libs-3.10.0-862.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-3.10.0'},
    {'reference':'kernel-tools-libs-devel-3.10.0-862.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-tools-libs-devel-3.10.0'},
    {'reference':'perf-3.10.0-862.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-3.10.0-862.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-abi-whitelists / kernel-debug / etc');
}
