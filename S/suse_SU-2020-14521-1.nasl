#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14521-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150542);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2020-0543",
    "CVE-2020-14364",
    "CVE-2020-15565",
    "CVE-2020-15567",
    "CVE-2020-25595",
    "CVE-2020-25596",
    "CVE-2020-25597",
    "CVE-2020-25600",
    "CVE-2020-25601",
    "CVE-2020-25603",
    "CVE-2020-25604"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14521-1");
  script_xref(name:"IAVB", value:"2020-B-0063-S");
  script_xref(name:"IAVB", value:"2020-B-0034-S");
  script_xref(name:"IAVB", value:"2020-B-0056-S");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2020:14521-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2020:14521-1 advisory.

  - Incomplete cleanup from specific special register read operations in some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2020-0543)

  - An out-of-bounds read/write access flaw was found in the USB emulator of the QEMU in versions before
    5.2.0. This issue occurs while processing USB packets from a guest when USBDevice 'setup_len' exceeds its
    'data_buf[4096]' in the do_token_in, do_token_out routines. This flaw allows a guest user to crash the
    QEMU process, resulting in a denial of service, or the potential execution of arbitrary code with the
    privileges of the QEMU process on the host. (CVE-2020-14364)

  - An issue was discovered in Xen through 4.13.x, allowing x86 Intel HVM guest OS users to cause a host OS
    denial of service or possibly gain privileges because of insufficient cache write-back under VT-d. When
    page tables are shared between IOMMU and CPU, changes to them require flushing of both TLBs. Furthermore,
    IOMMUs may be non-coherent, and hence prior to flushing IOMMU TLBs, a CPU cache also needs writing back to
    memory after changes were made. Such writing back of cached data was missing in particular when splitting
    large page mappings into smaller granularity ones. A malicious guest may be able to retain read/write DMA
    access to frames returned to Xen's free pool, and later reused for another purpose. Host crashes (leading
    to a Denial of Service) and privilege escalation cannot be ruled out. Xen versions from at least 3.2
    onwards are affected. Only x86 Intel systems are affected. x86 AMD as well as Arm systems are not
    affected. Only x86 HVM guests using hardware assisted paging (HAP), having a passed through PCI device
    assigned, and having page table sharing enabled can leverage the vulnerability. Note that page table
    sharing will be enabled (by default) only if Xen considers IOMMU and CPU large page size support
    compatible. (CVE-2020-15565)

  - An issue was discovered in Xen through 4.13.x, allowing Intel guest OS users to gain privileges or cause a
    denial of service because of non-atomic modification of a live EPT PTE. When mapping guest EPT (nested
    paging) tables, Xen would in some circumstances use a series of non-atomic bitfield writes. Depending on
    the compiler version and optimisation flags, Xen might expose a dangerous partially written PTE to the
    hardware, which an attacker might be able to race to exploit. A guest administrator or perhaps even an
    unprivileged guest user might be able to cause denial of service, data corruption, or privilege
    escalation. Only systems using Intel CPUs are vulnerable. Systems using AMD CPUs, and Arm systems, are not
    vulnerable. Only systems using nested paging (hap, aka nested paging, aka in this case Intel EPT) are
    vulnerable. Only HVM and PVH guests can exploit the vulnerability. The presence and scope of the
    vulnerability depends on the precise optimisations performed by the compiler used to build Xen. If the
    compiler generates (a) a single 64-bit write, or (b) a series of read-modify-write operations in the same
    order as the source code, the hypervisor is not vulnerable. For example, in one test build using GCC 8.3
    with normal settings, the compiler generated multiple (unlocked) read-modify-write operations in source-
    code order, which did not constitute a vulnerability. We have not been able to survey compilers;
    consequently we cannot say which compiler(s) might produce vulnerable code (with which code-generation
    options). The source code clearly violates the C rules, and thus should be considered vulnerable.
    (CVE-2020-15567)

  - An issue was discovered in Xen through 4.14.x. The PCI passthrough code improperly uses register data.
    Code paths in Xen's MSI handling have been identified that act on unsanitized values read back from device
    hardware registers. While devices strictly compliant with PCI specifications shouldn't be able to affect
    these registers, experience shows that it's very common for devices to have out-of-spec backdoor
    operations that can affect the result of these reads. A not fully trusted guest may be able to crash Xen,
    leading to a Denial of Service (DoS) for the entire system. Privilege escalation and information leaks
    cannot be excluded. All versions of Xen supporting PCI passthrough are affected. Only x86 systems are
    vulnerable. Arm systems are not vulnerable. Only guests with passed through PCI devices may be able to
    leverage the vulnerability. Only systems passing through devices with out-of-spec (backdoor)
    functionality can cause issues. Experience shows that such out-of-spec functionality is common; unless you
    have reason to believe that your device does not have such functionality, it's better to assume that it
    does. (CVE-2020-25595)

  - An issue was discovered in Xen through 4.14.x. x86 PV guest kernels can experience denial of service via
    SYSENTER. The SYSENTER instruction leaves various state sanitization activities to software. One of Xen's
    sanitization paths injects a #GP fault, and incorrectly delivers it twice to the guest. This causes the
    guest kernel to observe a kernel-privilege #GP fault (typically fatal) rather than a user-privilege #GP
    fault (usually converted into SIGSEGV/etc.). Malicious or buggy userspace can crash the guest kernel,
    resulting in a VM Denial of Service. All versions of Xen from 3.2 onwards are vulnerable. Only x86 systems
    are vulnerable. ARM platforms are not vulnerable. Only x86 systems that support the SYSENTER instruction
    in 64bit mode are vulnerable. This is believed to be Intel, Centaur, and Shanghai CPUs. AMD and Hygon CPUs
    are not believed to be vulnerable. Only x86 PV guests can exploit the vulnerability. x86 PVH / HVM guests
    cannot exploit the vulnerability. (CVE-2020-25596)

  - An issue was discovered in Xen through 4.14.x. There is mishandling of the constraint that once-valid
    event channels may not turn invalid. Logic in the handling of event channel operations in Xen assumes that
    an event channel, once valid, will not become invalid over the life time of a guest. However, operations
    like the resetting of all event channels may involve decreasing one of the bounds checked when determining
    validity. This may lead to bug checks triggering, crashing the host. An unprivileged guest may be able to
    crash Xen, leading to a Denial of Service (DoS) for the entire system. All Xen versions from 4.4 onwards
    are vulnerable. Xen versions 4.3 and earlier are not vulnerable. Only systems with untrusted guests
    permitted to create more than the default number of event channels are vulnerable. This number depends on
    the architecture and type of guest. For 32-bit x86 PV guests, this is 1023; for 64-bit x86 PV guests, and
    for all ARM guests, this number is 4095. Systems where untrusted guests are limited to fewer than this
    number are not vulnerable. Note that xl and libxl limit max_event_channels to 1023 by default, so systems
    using exclusively xl, libvirt+libxl, or their own toolstack based on libxl, and not explicitly setting
    max_event_channels, are not vulnerable. (CVE-2020-25597)

  - An issue was discovered in Xen through 4.14.x. Out of bounds event channels are available to 32-bit x86
    domains. The so called 2-level event channel model imposes different limits on the number of usable event
    channels for 32-bit x86 domains vs 64-bit or Arm (either bitness) ones. 32-bit x86 domains can use only
    1023 channels, due to limited space in their shared (between guest and Xen) information structure, whereas
    all other domains can use up to 4095 in this model. The recording of the respective limit during domain
    initialization, however, has occurred at a time where domains are still deemed to be 64-bit ones, prior to
    actually honoring respective domain properties. At the point domains get recognized as 32-bit ones, the
    limit didn't get updated accordingly. Due to this misbehavior in Xen, 32-bit domains (including Domain 0)
    servicing other domains may observe event channel allocations to succeed when they should really fail.
    Subsequent use of such event channels would then possibly lead to corruption of other parts of the shared
    info structure. An unprivileged guest may cause another domain, in particular Domain 0, to misbehave. This
    may lead to a Denial of Service (DoS) for the entire system. All Xen versions from 4.4 onwards are
    vulnerable. Xen versions 4.3 and earlier are not vulnerable. Only x86 32-bit domains servicing other
    domains are vulnerable. Arm systems, as well as x86 64-bit domains, are not vulnerable. (CVE-2020-25600)

  - An issue was discovered in Xen through 4.14.x. There is a lack of preemption in evtchn_reset() /
    evtchn_destroy(). In particular, the FIFO event channel model allows guests to have a large number of
    event channels active at a time. Closing all of these (when resetting all event channels or when cleaning
    up after the guest) may take extended periods of time. So far, there was no arrangement for preemption at
    suitable intervals, allowing a CPU to spend an almost unbounded amount of time in the processing of these
    operations. Malicious or buggy guest kernels can mount a Denial of Service (DoS) attack affecting the
    entire system. All Xen versions are vulnerable in principle. Whether versions 4.3 and older are vulnerable
    depends on underlying hardware characteristics. (CVE-2020-25601)

  - An issue was discovered in Xen through 4.14.x. There are missing memory barriers when accessing/allocating
    an event channel. Event channels control structures can be accessed lockless as long as the port is
    considered to be valid. Such a sequence is missing an appropriate memory barrier (e.g., smp_*mb()) to
    prevent both the compiler and CPU from re-ordering access. A malicious guest may be able to cause a
    hypervisor crash resulting in a Denial of Service (DoS). Information leak and privilege escalation cannot
    be excluded. Systems running all versions of Xen are affected. Whether a system is vulnerable will depend
    on the CPU and compiler used to build Xen. For all systems, the presence and the scope of the
    vulnerability depend on the precise re-ordering performed by the compiler used to build Xen. We have not
    been able to survey compilers; consequently we cannot say which compiler(s) might produce vulnerable code
    (with which code generation options). GCC documentation clearly suggests that re-ordering is possible. Arm
    systems will also be vulnerable if the CPU is able to re-order memory access. Please consult your CPU
    vendor. x86 systems are only vulnerable if a compiler performs re-ordering. (CVE-2020-25603)

  - An issue was discovered in Xen through 4.14.x. There is a race condition when migrating timers between x86
    HVM vCPUs. When migrating timers of x86 HVM guests between its vCPUs, the locking model used allows for a
    second vCPU of the same guest (also operating on the timers) to release a lock that it didn't acquire. The
    most likely effect of the issue is a hang or crash of the hypervisor, i.e., a Denial of Service (DoS). All
    versions of Xen are affected. Only x86 systems are vulnerable. Arm systems are not vulnerable. Only x86
    HVM guests can leverage the vulnerability. x86 PV and PVH cannot leverage the vulnerability. Only guests
    with more than one vCPU can exploit the vulnerability. (CVE-2020-25604)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1173380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176343");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176350");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-October/007611.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d37166ab");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-0543");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14364");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15565");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15567");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25595");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25596");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25600");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25604");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25597");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-15565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'xen-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-doc-html-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_44_3.0.101_108.117-61.55', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_44_3.0.101_108.117-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-pae-4.4.4_44_3.0.101_108.117-61.55', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-32bit-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-4.4.4_44-61.55', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_44-61.55', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-doc-html-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_44_3.0.101_108.117-61.55', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_44_3.0.101_108.117-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-pae-4.4.4_44_3.0.101_108.117-61.55', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-32bit-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-4.4.4_44-61.55', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_44-61.55', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_44-61.55', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen / xen-doc-html / xen-kmp-default / xen-kmp-pae / xen-libs / etc');
}
