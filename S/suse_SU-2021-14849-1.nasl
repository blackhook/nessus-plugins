#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14849-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155814);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2014-7841",
    "CVE-2020-36385",
    "CVE-2021-3542",
    "CVE-2021-3609",
    "CVE-2021-3640",
    "CVE-2021-3653",
    "CVE-2021-3655",
    "CVE-2021-3679",
    "CVE-2021-3772",
    "CVE-2021-20265",
    "CVE-2021-33033",
    "CVE-2021-37159",
    "CVE-2021-38160",
    "CVE-2021-38198",
    "CVE-2021-42008",
    "CVE-2021-42739",
    "CVE-2021-43389"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14849-1");

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2021:14849-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14849-1 advisory.

  - The sctp_process_param function in net/sctp/sm_make_chunk.c in the SCTP implementation in the Linux kernel
    before 3.17.4, when ASCONF is used, allows remote attackers to cause a denial of service (NULL pointer
    dereference and system crash) via a malformed INIT chunk. (CVE-2014-7841)

  - An issue was discovered in the Linux kernel before 5.10. drivers/infiniband/core/ucma.c has a use-after-
    free because the ctx is reached via the ctx_list in some ucma_migrate_id situations where ucma_close is
    called, aka CID-f5449e74802c. (CVE-2020-36385)

  - A flaw was found in the way memory resources were freed in the unix_stream_recvmsg function in the Linux
    kernel when a signal was pending. This flaw allows an unprivileged local user to crash the system by
    exhausting available memory. The highest threat from this vulnerability is to system availability.
    (CVE-2021-20265)

  - The Linux kernel before 5.11.14 has a use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c because
    the CIPSO and CALIPSO refcounting for the DOI definitions is mishandled, aka CID-ad5d07f4a9cd. This leads
    to writing an arbitrary value. (CVE-2021-33033)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2021-42739. Reason: This candidate is a
    reservation duplicate of CVE-2021-42739. Notes: All CVE users should reference CVE-2021-42739 instead of
    this candidate. All references and descriptions in this candidate have been removed to prevent accidental
    usage. (CVE-2021-3542)

  - kernel: race condition in net/can/bcm.c leads to local privilege escalation (CVE-2021-3609)

  - A flaw was found in the KVM's AMD code for supporting SVM nested virtualization. The flaw occurs when
    processing the VMCB (virtual machine control block) provided by the L1 guest to spawn/handle a nested
    guest (L2). Due to improper validation of the int_ctl field, this issue could allow a malicious L1 to
    enable AVIC support (Advanced Virtual Interrupt Controller) for the L2 guest. As a result, the L2 guest
    would be allowed to read/write physical pages of the host, resulting in a crash of the entire system, leak
    of sensitive data or potential guest-to-host escape. This flaw affects Linux kernel versions prior to
    5.14-rc7. (CVE-2021-3653)

  - A vulnerability was found in the Linux kernel in versions prior to v5.14-rc1. Missing size validations on
    inbound SCTP packets may allow the kernel to read uninitialized memory. (CVE-2021-3655)

  - A lack of CPU resource in the Linux kernel tracing module functionality in versions prior to 5.14-rc3 was
    found in the way user uses trace ring buffer in a specific way. Only privileged local users (with
    CAP_SYS_ADMIN capability) could use this flaw to starve the resources causing denial of service.
    (CVE-2021-3679)

  - hso_free_net_device in drivers/net/usb/hso.c in the Linux kernel through 5.13.4 calls unregister_netdev
    without checking for the NETREG_REGISTERED state, leading to a use-after-free and a double free.
    (CVE-2021-37159)

  - ** DISPUTED ** In drivers/char/virtio_console.c in the Linux kernel before 5.13.4, data corruption or loss
    can be triggered by an untrusted device that supplies a buf->len value exceeding the buffer size. NOTE:
    the vendor indicates that the cited data corruption is not a vulnerability in any existing use case; the
    length validation was added solely for robustness in the face of anomalous host OS behavior.
    (CVE-2021-38160)

  - arch/x86/kvm/mmu/paging_tmpl.h in the Linux kernel before 5.12.11 incorrectly computes the access
    permissions of a shadow page, leading to a missing guest protection page fault. (CVE-2021-38198)

  - The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab
    out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.
    (CVE-2021-42008)

  - The firewire subsystem in the Linux kernel through 5.14.13 has a buffer overflow related to
    drivers/media/firewire/firedtv-avc.c and drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt
    mishandles bounds checking. (CVE-2021-42739)

  - An issue was discovered in the Linux kernel before 5.14.15. There is an array-index-out-of-bounds flaw in
    the detach_capi_ctr function in drivers/isdn/capi/kcapi.c. (CVE-2021-43389)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/904899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/905100");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183089");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187215");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188172");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188876");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190117");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190351");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191315");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191660");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192267");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-December/009784.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?baa8927b");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-7841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-36385");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20265");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33033");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3542");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3609");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3640");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3653");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3655");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3679");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37159");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3772");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38160");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-38198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42008");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-42739");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43389");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38160");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigmem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ppc64-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'kernel-default-3.0.101-108.132.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-base-3.0.101-108.132.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-devel-3.0.101-108.132.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-default-man-3.0.101-108.132.1', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.132.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-3.0.101-108.132.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.132.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-base-3.0.101-108.132.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.132.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-ec2-devel-3.0.101-108.132.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-3.0.101-108.132.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-base-3.0.101-108.132.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-pae-devel-3.0.101-108.132.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-source-3.0.101-108.132.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-syms-3.0.101-108.132.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-3.0.101-108.132.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-base-3.0.101-108.132.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-trace-devel-3.0.101-108.132.1', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.132.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-3.0.101-108.132.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.132.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-base-3.0.101-108.132.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.132.1', 'sp':'4', 'cpu':'i586', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'kernel-xen-devel-3.0.101-108.132.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-default / kernel-default-base / kernel-default-devel / etc');
}
