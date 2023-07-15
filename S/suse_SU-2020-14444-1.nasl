#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14444-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150584);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id(
    "CVE-2018-12207",
    "CVE-2019-11135",
    "CVE-2019-18420",
    "CVE-2019-18421",
    "CVE-2019-18424",
    "CVE-2019-18425",
    "CVE-2019-19577",
    "CVE-2019-19578",
    "CVE-2019-19579",
    "CVE-2019-19580",
    "CVE-2019-19583",
    "CVE-2020-7211",
    "CVE-2020-8608",
    "CVE-2020-11740",
    "CVE-2020-11741",
    "CVE-2020-11742"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14444-1");
  script_xref(name:"IAVB", value:"2019-B-0084-S");
  script_xref(name:"IAVB", value:"2019-B-0091-S");
  script_xref(name:"IAVB", value:"2020-B-0023-S");

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2020:14444-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2020:14444-1 advisory.

  - Improper invalidation for page table updates by a virtual guest operating system for multiple Intel(R)
    Processors may allow an authenticated user to potentially enable denial of service of the host system via
    local access. (CVE-2018-12207)

  - TSX Asynchronous Abort condition on some CPUs utilizing speculative execution may allow an authenticated
    user to potentially enable information disclosure via a side channel with local access. (CVE-2019-11135)

  - An issue was discovered in Xen through 4.12.x allowing x86 PV guest OS users to cause a denial of service
    via a VCPUOP_initialise hypercall. hypercall_create_continuation() is a variadic function which uses a
    printf-like format string to interpret its parameters. Error handling for a bad format character was done
    using BUG(), which crashes Xen. One path, via the VCPUOP_initialise hypercall, has a bad format character.
    The BUG() can be hit if VCPUOP_initialise executes for a sufficiently long period of time for a
    continuation to be created. Malicious guests may cause a hypervisor crash, resulting in a Denial of
    Service (DoS). Xen versions 4.6 and newer are vulnerable. Xen versions 4.5 and earlier are not vulnerable.
    Only x86 PV guests can exploit the vulnerability. HVM and PVH guests, and guests on ARM systems, cannot
    exploit the vulnerability. (CVE-2019-18420)

  - An issue was discovered in Xen through 4.12.x allowing x86 PV guest OS users to gain host OS privileges by
    leveraging race conditions in pagetable promotion and demotion operations. There are issues with
    restartable PV type change operations. To avoid using shadow pagetables for PV guests, Xen exposes the
    actual hardware pagetables to the guest. In order to prevent the guest from modifying these page tables
    directly, Xen keeps track of how pages are used using a type system; pages must be promoted before being
    used as a pagetable, and demoted before being used for any other type. Xen also allows for recursive
    promotions: i.e., an operating system promoting a page to an L4 pagetable may end up causing pages to be
    promoted to L3s, which may in turn cause pages to be promoted to L2s, and so on. These operations may take
    an arbitrarily large amount of time, and so must be re-startable. Unfortunately, making recursive
    pagetable promotion and demotion operations restartable is incredibly complicated, and the code contains
    several races which, if triggered, can cause Xen to drop or retain extra type counts, potentially allowing
    guests to get write access to in-use pagetables. A malicious PV guest administrator may be able to
    escalate their privilege to that of the host. All x86 systems with untrusted PV guests are vulnerable. HVM
    and PVH guests cannot exercise this vulnerability. (CVE-2019-18421)

  - An issue was discovered in Xen through 4.12.x allowing attackers to gain host OS privileges via DMA in a
    situation where an untrusted domain has access to a physical device. This occurs because passed through
    PCI devices may corrupt host memory after deassignment. When a PCI device is assigned to an untrusted
    domain, it is possible for that domain to program the device to DMA to an arbitrary address. The IOMMU is
    used to protect the host from malicious DMA by making sure that the device addresses can only target
    memory assigned to the guest. However, when the guest domain is torn down, or the device is deassigned,
    the device is assigned back to dom0, thus allowing any in-flight DMA to potentially target critical host
    data. An untrusted domain with access to a physical device can DMA into host memory, leading to privilege
    escalation. Only systems where guests are given direct access to physical devices capable of DMA (PCI
    pass-through) are vulnerable. Systems which do not use PCI pass-through are not vulnerable.
    (CVE-2019-18424)

  - An issue was discovered in Xen through 4.12.x allowing 32-bit PV guest OS users to gain guest OS
    privileges by installing and using descriptors. There is missing descriptor table limit checking in x86 PV
    emulation. When emulating certain PV guest operations, descriptor table accesses are performed by the
    emulating code. Such accesses should respect the guest specified limits, unless otherwise guaranteed to
    fail in such a case. Without this, emulation of 32-bit guest user mode calls through call gates would
    allow guest user mode to install and then use descriptors of their choice, as long as the guest kernel did
    not itself install an LDT. (Most OSes don't install any LDT by default). 32-bit PV guest user mode can
    elevate its privileges to that of the guest kernel. Xen versions from at least 3.2 onwards are affected.
    Only 32-bit PV guest user mode can leverage this vulnerability. HVM, PVH, as well as 64-bit PV guests
    cannot leverage this vulnerability. Arm systems are unaffected. (CVE-2019-18425)

  - An issue was discovered in Xen through 4.12.x allowing x86 AMD HVM guest OS users to cause a denial of
    service or possibly gain privileges by triggering data-structure access during pagetable-height updates.
    When running on AMD systems with an IOMMU, Xen attempted to dynamically adapt the number of levels of
    pagetables (the pagetable height) in the IOMMU according to the guest's address space size. The code to
    select and update the height had several bugs. Notably, the update was done without taking a lock which is
    necessary for safe operation. A malicious guest administrator can cause Xen to access data structures
    while they are being modified, causing Xen to crash. Privilege escalation is thought to be very difficult
    but cannot be ruled out. Additionally, there is a potential memory leak of 4kb per guest boot, under
    memory pressure. Only Xen on AMD CPUs is vulnerable. Xen running on Intel CPUs is not vulnerable. ARM
    systems are not vulnerable. Only systems where guests are given direct access to physical devices are
    vulnerable. Systems which do not use PCI pass-through are not vulnerable. Only HVM guests can exploit the
    vulnerability. PV and PVH guests cannot. All versions of Xen with IOMMU support are vulnerable.
    (CVE-2019-19577)

  - An issue was discovered in Xen through 4.12.x allowing x86 PV guest OS users to cause a denial of service
    via degenerate chains of linear pagetables, because of an incorrect fix for CVE-2017-15595. Linear
    pagetables is a technique which involves either pointing a pagetable at itself, or to another pagetable
    of the same or higher level. Xen has limited support for linear pagetables: A page may either point to
    itself, or point to another pagetable of the same level (i.e., L2 to L2, L3 to L3, and so on). XSA-240
    introduced an additional restriction that limited the depth of such chains by allowing pages to either
    *point to* other pages of the same level, or *be pointed to* by other pages of the same level, but not
    both. To implement this, we keep track of the number of outstanding times a page points to or is pointed
    to another page table, to prevent both from happening at the same time. Unfortunately, the original commit
    introducing this reset this count when resuming validation of a partially-validated pagetable, incorrectly
    dropping some linear_pt_entry counts. If an attacker could engineer such a situation to occur, they
    might be able to make loops or other arbitrary chains of linear pagetables, as described in XSA-240. A
    malicious or buggy PV guest may cause the hypervisor to crash, resulting in Denial of Service (DoS)
    affecting the entire host. Privilege escalation and information leaks cannot be excluded. All versions of
    Xen are vulnerable. Only x86 systems are affected. Arm systems are not affected. Only x86 PV guests can
    leverage the vulnerability. x86 HVM and PVH guests cannot leverage the vulnerability. Only systems which
    have enabled linear pagetables are vulnerable. Systems which have disabled linear pagetables, either by
    selecting CONFIG_PV_LINEAR_PT=n when building the hypervisor, or adding pv-linear-pt=false on the command-
    line, are not vulnerable. (CVE-2019-19578)

  - An issue was discovered in Xen through 4.12.x allowing attackers to gain host OS privileges via DMA in a
    situation where an untrusted domain has access to a physical device (and assignable-add is not used),
    because of an incomplete fix for CVE-2019-18424. XSA-302 relies on the use of libxl's assignable-add
    feature to prepare devices to be assigned to untrusted guests. Unfortunately, this is not considered a
    strictly required step for device assignment. The PCI passthrough documentation on the wiki describes
    alternate ways of preparing devices for assignment, and libvirt uses its own ways as well. Hosts where
    these alternate methods are used will still leave the system in a vulnerable state after the device
    comes back from a guest. An untrusted domain with access to a physical device can DMA into host memory,
    leading to privilege escalation. Only systems where guests are given direct access to physical devices
    capable of DMA (PCI pass-through) are vulnerable. Systems which do not use PCI pass-through are not
    vulnerable. (CVE-2019-19579)

  - An issue was discovered in Xen through 4.12.x allowing x86 PV guest OS users to gain host OS privileges by
    leveraging race conditions in pagetable promotion and demotion operations, because of an incomplete fix
    for CVE-2019-18421. XSA-299 addressed several critical issues in restartable PV type change operations.
    Despite extensive testing and auditing, some corner cases were missed. A malicious PV guest administrator
    may be able to escalate their privilege to that of the host. All security-supported versions of Xen are
    vulnerable. Only x86 systems are affected. Arm systems are not affected. Only x86 PV guests can leverage
    the vulnerability. x86 HVM and PVH guests cannot leverage the vulnerability. Note that these attacks
    require very precise timing, which may be difficult to exploit in practice. (CVE-2019-19580)

  - An issue was discovered in Xen through 4.12.x allowing x86 HVM/PVH guest OS users to cause a denial of
    service (guest OS crash) because VMX VMEntry checks mishandle a certain case. Please see XSA-260 for
    background on the MovSS shadow. Please see XSA-156 for background on the need for #DB interception. The
    VMX VMEntry checks do not like the exact combination of state which occurs when #DB in intercepted, Single
    Stepping is active, and blocked by STI/MovSS is active, despite this being a legitimate state to be in.
    The resulting VMEntry failure is fatal to the guest. HVM/PVH guest userspace code may be able to crash the
    guest, resulting in a guest Denial of Service. All versions of Xen are affected. Only systems supporting
    VMX hardware virtual extensions (Intel, Cyrix, or Zhaoxin CPUs) are affected. Arm and AMD systems are
    unaffected. Only HVM/PVH guests are affected. PV guests cannot leverage the vulnerability.
    (CVE-2019-19583)

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

  - tftp.c in libslirp 4.1.0, as used in QEMU 4.2.0, does not prevent ..\ directory traversal on Windows.
    (CVE-2020-7211)

  - In libslirp 4.1.0, as used in QEMU 4.2.0, tcp_subr.c misuses snprintf return values, leading to a buffer
    overflow in later code. (CVE-2020-8608)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1152497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154448");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154456");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154461");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1155945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1157888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1158007");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1161181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1163019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1168140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1169392");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174543");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-August/007221.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9877cfc1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-12207");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18420");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18421");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18424");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-18425");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19577");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19578");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19579");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11741");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11742");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-7211");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8608");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18425");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/04");
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

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'xen-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-doc-html-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_42_3.0.101_108.114-61.52', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_42_3.0.101_108.114-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-kmp-pae-4.4.4_42_3.0.101_108.114-61.52', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-32bit-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-4.4.4_42-61.52', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-libs-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_42-61.52', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'xen-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-doc-html-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_42_3.0.101_108.114-61.52', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-default-4.4.4_42_3.0.101_108.114-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-kmp-pae-4.4.4_42_3.0.101_108.114-61.52', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-32bit-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-4.4.4_42-61.52', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-libs-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_42-61.52', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'xen-tools-domU-4.4.4_42-61.52', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
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
      severity   : SECURITY_HOLE,
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
