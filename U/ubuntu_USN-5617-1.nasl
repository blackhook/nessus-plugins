#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5617-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165248);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-0543",
    "CVE-2020-11739",
    "CVE-2020-11740",
    "CVE-2020-11741",
    "CVE-2020-11742",
    "CVE-2020-11743",
    "CVE-2020-15563",
    "CVE-2020-15564",
    "CVE-2020-15565",
    "CVE-2020-15566",
    "CVE-2020-15567",
    "CVE-2020-25595",
    "CVE-2020-25596",
    "CVE-2020-25597",
    "CVE-2020-25599",
    "CVE-2020-25600",
    "CVE-2020-25601",
    "CVE-2020-25602",
    "CVE-2020-25603",
    "CVE-2020-25604"
  );
  script_xref(name:"USN", value:"5617-1");

  script_name(english:"Ubuntu 20.04 LTS : Xen vulnerabilities (USN-5617-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5617-1 advisory.

  - Incomplete cleanup from specific special register read operations in some Intel(R) Processors may allow an
    authenticated user to potentially enable information disclosure via local access. (CVE-2020-0543)

  - An issue was discovered in Xen through 4.13.x, allowing guest OS users to cause a denial of service or
    possibly gain privileges because of missing memory barriers in read-write unlock paths. The read-write
    unlock paths don't contain a memory barrier. On Arm, this means a processor is allowed to re-order the
    memory access with the preceding ones. In other words, the unlock may be seen by another processor before
    all the memory accesses within the critical section. As a consequence, it may be possible to have a
    writer executing a critical section at the same time as readers or another writer. In other words, many of
    the assumptions (e.g., a variable cannot be modified after a check) in the critical sections are not safe
    anymore. The read-write locks are used in hypercalls (such as grant-table ones), so a malicious guest
    could exploit the race. For instance, there is a small window where Xen can leak memory if
    XENMAPSPACE_grant_table is used concurrently. A malicious guest may be able to leak memory, or cause a
    hypervisor crash resulting in a Denial of Service (DoS). Information leak and privilege escalation cannot
    be excluded. (CVE-2020-11739)

  - An issue was discovered in xenoprof in Xen through 4.13.x, allowing guest OS users (without active
    profiling) to obtain sensitive information about other guests. Unprivileged guests can request to map
    xenoprof buffers, even if profiling has not been enabled for those guests. These buffers were not
    scrubbed. (CVE-2020-11740)

  - An issue was discovered in xenoprof in Xen through 4.13.x, allowing guest OS users (with active profiling)
    to obtain sensitive information about other guests, cause a denial of service, or possibly gain
    privileges. For guests for which active profiling was enabled by the administrator, the xenoprof code
    uses the standard Xen shared ring structure. Unfortunately, this code did not treat the guest as a
    potential adversary: it trusts the guest not to modify buffer size information or modify head / tail
    pointers in unexpected ways. This can crash the host (DoS). Privilege escalation cannot be ruled out.
    (CVE-2020-11741)

  - An issue was discovered in Xen through 4.13.x, allowing guest OS users to cause a denial of service
    because of bad continuation handling in GNTTABOP_copy. Grant table operations are expected to return 0 for
    success, and a negative number for errors. The fix for CVE-2017-12135 introduced a path through grant copy
    handling where success may be returned to the caller without any action taken. In particular, the status
    fields of individual operations are left uninitialised, and may result in errant behaviour in the caller
    of GNTTABOP_copy. A buggy or malicious guest can construct its grant table in such a way that, when a
    backend domain tries to copy a grant, it hits the incorrect exit path. This returns success to the caller
    without doing anything, which may cause crashes or other incorrect behaviour. (CVE-2020-11742)

  - An issue was discovered in Xen through 4.13.x, allowing guest OS users to cause a denial of service
    because of a bad error path in GNTTABOP_map_grant. Grant table operations are expected to return 0 for
    success, and a negative number for errors. Some misplaced brackets cause one error path to return 1
    instead of a negative value. The grant table code in Linux treats this condition as success, and proceeds
    with incorrectly initialised state. A buggy or malicious guest can construct its grant table in such a way
    that, when a backend domain tries to map a grant, it hits the incorrect error path. This will crash a
    Linux based dom0 or backend domain. (CVE-2020-11743)

  - An issue was discovered in Xen through 4.13.x, allowing x86 HVM guest OS users to cause a hypervisor
    crash. An inverted conditional in x86 HVM guests' dirty video RAM tracking code allows such guests to make
    Xen de-reference a pointer guaranteed to point at unmapped space. A malicious or buggy HVM guest may cause
    the hypervisor to crash, resulting in Denial of Service (DoS) affecting the entire host. Xen versions from
    4.8 onwards are affected. Xen versions 4.7 and earlier are not affected. Only x86 systems are affected.
    Arm systems are not affected. Only x86 HVM guests using shadow paging can leverage the vulnerability. In
    addition, there needs to be an entity actively monitoring a guest's video frame buffer (typically for
    display purposes) in order for such a guest to be able to leverage the vulnerability. x86 PV guests, as
    well as x86 HVM guests using hardware assisted paging (HAP), cannot leverage the vulnerability.
    (CVE-2020-15563)

  - An issue was discovered in Xen through 4.13.x, allowing Arm guest OS users to cause a hypervisor crash
    because of a missing alignment check in VCPUOP_register_vcpu_info. The hypercall VCPUOP_register_vcpu_info
    is used by a guest to register a shared region with the hypervisor. The region will be mapped into Xen
    address space so it can be directly accessed. On Arm, the region is accessed with instructions that
    require a specific alignment. Unfortunately, there is no check that the address provided by the guest will
    be correctly aligned. As a result, a malicious guest could cause a hypervisor crash by passing a
    misaligned address. A malicious guest administrator may cause a hypervisor crash, resulting in a Denial of
    Service (DoS). All Xen versions are vulnerable. Only Arm systems are vulnerable. x86 systems are not
    affected. (CVE-2020-15564)

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

  - An issue was discovered in Xen through 4.13.x, allowing guest OS users to cause a host OS crash because of
    incorrect error handling in event-channel port allocation. The allocation of an event-channel port may
    fail for multiple reasons: (1) port is already in use, (2) the memory allocation failed, or (3) the port
    we try to allocate is higher than what is supported by the ABI (e.g., 2L or FIFO) used by the guest or the
    limit set by an administrator (max_event_channels in xl cfg). Due to the missing error checks, only (1)
    will be considered an error. All the other cases will provide a valid port and will result in a crash when
    trying to access the event channel. When the administrator configured a guest to allow more than 1023
    event channels, that guest may be able to crash the host. When Xen is out-of-memory, allocation of new
    event channels will result in crashing the host rather than reporting an error. Xen versions 4.10 and
    later are affected. All architectures are affected. The default configuration, when guests are created
    with xl/libxl, is not vulnerable, because of the default event-channel limit. (CVE-2020-15566)

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

  - An issue was discovered in Xen through 4.14.x. There are evtchn_reset() race conditions. Uses of
    EVTCHNOP_reset (potentially by a guest on itself) or XEN_DOMCTL_soft_reset (by itself covered by XSA-77)
    can lead to the violation of various internal assumptions. This may lead to out of bounds memory accesses
    or triggering of bug checks. In particular, x86 PV guests may be able to elevate their privilege to that
    of the host. Host and guest crashes are also possible, leading to a Denial of Service (DoS). Information
    leaks cannot be ruled out. All Xen versions from 4.5 onwards are vulnerable. Xen versions 4.4 and earlier
    are not vulnerable. (CVE-2020-25599)

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

  - An issue was discovered in Xen through 4.14.x. An x86 PV guest can trigger a host OS crash when handling
    guest access to MSR_MISC_ENABLE. When a guest accesses certain Model Specific Registers, Xen first reads
    the value from hardware to use as the basis for auditing the guest access. For the MISC_ENABLE MSR, which
    is an Intel specific MSR, this MSR read is performed without error handling for a #GP fault, which is the
    consequence of trying to read this MSR on non-Intel hardware. A buggy or malicious PV guest administrator
    can crash Xen, resulting in a host Denial of Service. Only x86 systems are vulnerable. ARM systems are not
    vulnerable. Only Xen versions 4.11 and onwards are vulnerable. 4.10 and earlier are not vulnerable. Only
    x86 systems that do not implement the MISC_ENABLE MSR (0x1a0) are vulnerable. AMD and Hygon systems do not
    implement this MSR and are vulnerable. Intel systems do implement this MSR and are not vulnerable. Other
    manufacturers have not been checked. Only x86 PV guests can exploit the vulnerability. x86 HVM/PVH guests
    cannot exploit the vulnerability. (CVE-2020-25602)

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5617-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11741");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-15565");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxen-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxencall1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxendevicemodel1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxenevtchn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxenforeignmemory1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxengnttab1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxenmisc4.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxenstore3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxentoolcore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxentoollog1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.11-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.11-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.11-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.9-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.9-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-4.9-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-hypervisor-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-system-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-system-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-system-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-utils-4.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xen-utils-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xenstore-utils");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libxen-dev', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxencall1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxendevicemodel1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxenevtchn1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxenforeignmemory1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxengnttab1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxenmisc4.11', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxenstore3.0', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxentoolcore1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'libxentoollog1', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.11-amd64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.11-arm64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.11-armhf', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.9-amd64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.9-arm64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-4.9-armhf', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-hypervisor-common', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-system-amd64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-system-arm64', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-system-armhf', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-utils-4.11', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xen-utils-common', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'},
    {'osver': '20.04', 'pkgname': 'xenstore-utils', 'pkgver': '4.11.3+24-g14b62ab3e5-1ubuntu2.3'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxen-dev / libxencall1 / libxendevicemodel1 / libxenevtchn1 / etc');
}
