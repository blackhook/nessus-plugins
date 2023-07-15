##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were
# extracted from OracleVM Security Advisory OVMSA-2021-0014.
##

include('compat.inc');

if (description)
{
  script_id(150180);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2020-25595",
    "CVE-2020-25597",
    "CVE-2020-25599",
    "CVE-2020-25600",
    "CVE-2020-25601",
    "CVE-2020-25603",
    "CVE-2020-25604",
    "CVE-2020-27671",
    "CVE-2020-27672",
    "CVE-2020-29480",
    "CVE-2020-29481",
    "CVE-2020-29483",
    "CVE-2020-29484",
    "CVE-2020-29570"
  );

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2021-0014)");

  script_set_attribute(attribute:"synopsis", value:
"The remote OracleVM host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote OracleVM system is missing necessary patches to address security updates:

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

  - An issue was discovered in Xen through 4.14.x allowing x86 HVM and PVH guest OS users to cause a denial of
    service (data corruption), cause a data leak, or possibly gain privileges because coalescing of per-page
    IOMMU TLB flushes is mishandled. (CVE-2020-27671)

  - An issue was discovered in Xen through 4.14.x allowing x86 guest OS users to cause a host OS denial of
    service, achieve data corruption, or possibly gain privileges by exploiting a race condition that leads to
    a use-after-free involving 2MiB and 1GiB superpages. (CVE-2020-27672)

  - Xen through 4.14.x allows guest OS administrators to obtain sensitive information (such as AES keys from
    outside the guest) via a side-channel attack on a power/energy monitoring interface, aka a Platypus
    attack. NOTE: there is only one logically independent fix: to change the access control for each such
    interface in Xen. (CVE-2020-28368)

  - An issue was discovered in Xen through 4.14.x allowing x86 HVM guest OS users to cause a denial of service
    (stack corruption), cause a data leak, or possibly gain privileges because of an off-by-one error. NOTE:
    this issue is caused by an incorrect fix for CVE-2020-27671. (CVE-2020-29040)

  - An issue was discovered in Xen through 4.14.x. Neither xenstore implementation does any permission checks
    when reporting a xenstore watch event. A guest administrator can watch the root xenstored node, which will
    cause notifications for every created, modified, and deleted key. A guest administrator can also use the
    special watches, which will cause a notification every time a domain is created and destroyed. Data may
    include: number, type, and domids of other VMs; existence and domids of driver domains; numbers of virtual
    interfaces, block devices, vcpus; existence of virtual framebuffers and their backend style (e.g.,
    existence of VNC service); Xen VM UUIDs for other domains; timing information about domain creation and
    device setup; and some hints at the backend provisioning of VMs and their devices. The watch events do not
    contain values stored in xenstore, only key names. A guest administrator can observe non-sensitive domain
    and device lifecycle events relating to other guests. This information allows some insight into overall
    system configuration (including the number and general nature of other guests), and configuration of other
    guests (including the number and general nature of other guests' devices). This information might be
    commercially interesting or might make other attacks easier. There is not believed to be exposure of
    sensitive data. Specifically, there is no exposure of VNC passwords, port numbers, pathnames in host and
    guest filesystems, cryptographic keys, or within-guest data. (CVE-2020-29480)

  - An issue was discovered in Xen through 4.14.x. Access rights of Xenstore nodes are per domid.
    Unfortunately, existing granted access rights are not removed when a domain is being destroyed. This means
    that a new domain created with the same domid will inherit the access rights to Xenstore nodes from the
    previous domain(s) with the same domid. Because all Xenstore entries of a guest below
    /local/domain/<domid> are being deleted by Xen tools when a guest is destroyed, only Xenstore entries of
    other guests still running are affected. For example, a newly created guest domain might be able to read
    sensitive information that had belonged to a previously existing guest domain. Both Xenstore
    implementations (C and Ocaml) are vulnerable. (CVE-2020-29481)

  - An issue was discovered in Xen through 4.14.x. Xenstored and guests communicate via a shared memory page
    using a specific protocol. When a guest violates this protocol, xenstored will drop the connection to that
    guest. Unfortunately, this is done by just removing the guest from xenstored's internal management,
    resulting in the same actions as if the guest had been destroyed, including sending an @releaseDomain
    event. @releaseDomain events do not say that the guest has been removed. All watchers of this event must
    look at the states of all guests to find the guest that has been removed. When an @releaseDomain is
    generated due to a domain xenstored protocol violation, because the guest is still running, the watchers
    will not react. Later, when the guest is actually destroyed, xenstored will no longer have it stored in
    its internal data base, so no further @releaseDomain event will be sent. This can lead to a zombie domain;
    memory mappings of that guest's memory will not be removed, due to the missing event. This zombie domain
    will be cleaned up only after another domain is destroyed, as that will trigger another @releaseDomain
    event. If the device model of the guest that violated the Xenstore protocol is running in a stub-domain, a
    use-after-free case could happen in xenstored, after having removed the guest from its internal data base,
    possibly resulting in a crash of xenstored. A malicious guest can block resources of the host for a period
    after its own death. Guests with a stub domain device model can eventually crash xenstored, resulting in a
    more serious denial of service (the prevention of any further domain management operations). Only the C
    variant of Xenstore is affected; the Ocaml variant is not affected. Only HVM guests with a stubdom device
    model can cause a serious DoS. (CVE-2020-29483)

  - An issue was discovered in Xen through 4.14.x. When a Xenstore watch fires, the xenstore client that
    registered the watch will receive a Xenstore message containing the path of the modified Xenstore entry
    that triggered the watch, and the tag that was specified when registering the watch. Any communication
    with xenstored is done via Xenstore messages, consisting of a message header and the payload. The payload
    length is limited to 4096 bytes. Any request to xenstored resulting in a response with a payload longer
    than 4096 bytes will result in an error. When registering a watch, the payload length limit applies to the
    combined length of the watched path and the specified tag. Because watches for a specific path are also
    triggered for all nodes below that path, the payload of a watch event message can be longer than the
    payload needed to register the watch. A malicious guest that registers a watch using a very large tag
    (i.e., with a registration operation payload length close to the 4096 byte limit) can cause the generation
    of watch events with a payload length larger than 4096 bytes, by writing to Xenstore entries below the
    watched path. This will result in an error condition in xenstored. This error can result in a NULL pointer
    dereference, leading to a crash of xenstored. A malicious guest administrator can cause xenstored to
    crash, leading to a denial of service. Following a xenstored crash, domains may continue to run, but
    management operations will be impossible. Only C xenstored is affected, oxenstored is not affected.
    (CVE-2020-29484)

  - An issue was discovered in Xen through 4.14.x. Recording of the per-vCPU control block mapping maintained
    by Xen and that of pointers into the control block is reversed. The consumer assumes, seeing the former
    initialized, that the latter are also ready for use. Malicious or buggy guest kernels can mount a Denial
    of Service (DoS) attack affecting the entire system. (CVE-2020-29570)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-25595.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-25597.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-25599.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-25600.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-25601.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-25603.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-25604.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-27671.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-27672.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-28368.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-29040.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-29480.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-29481.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-29483.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-29484.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/cve/CVE-2020-29570.html");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/OVMSA-2021-0014.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected xen / xen-tools packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27672");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-29481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"OracleVM Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

var pkgs = [
    {'reference':'xen-4.4.4-222.0.38.el6', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'xen-4.4.4-222'},
    {'reference':'xen-tools-4.4.4-222.0.38.el6', 'cpu':'x86_64', 'release':'3.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'xen-tools-4.4.4-222'}
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
  if (!empty_or_null(package_array['release'])) release = 'OVS' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen / xen-tools');
}
