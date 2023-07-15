#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:7933. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167544);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/02");

  script_cve_id(
    "CVE-2020-36516",
    "CVE-2021-3640",
    "CVE-2022-0168",
    "CVE-2022-0617",
    "CVE-2022-0854",
    "CVE-2022-1016",
    "CVE-2022-1048",
    "CVE-2022-1184",
    "CVE-2022-1280",
    "CVE-2022-1353",
    "CVE-2022-1679",
    "CVE-2022-1852",
    "CVE-2022-1998",
    "CVE-2022-2586",
    "CVE-2022-2639",
    "CVE-2022-20368",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21166",
    "CVE-2022-21499",
    "CVE-2022-23816",
    "CVE-2022-23825",
    "CVE-2022-24448",
    "CVE-2022-26373",
    "CVE-2022-28390",
    "CVE-2022-28893",
    "CVE-2022-29581",
    "CVE-2022-29900",
    "CVE-2022-29901",
    "CVE-2022-36946",
    "CVE-2022-39190"
  );
  script_xref(name:"RHSA", value:"2022:7933");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"RHEL 9 : kernel-rt (RHSA-2022:7933)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:7933 advisory.

  - kernel: off-path attacker may inject data or terminate victim's TCP session (CVE-2020-36516)

  - kernel: use-after-free vulnerability in function sco_sock_sendmsg() (CVE-2021-3640)

  - kernel: smb2_ioctl_query_info NULL pointer dereference (CVE-2022-0168)

  - kernel: NULL pointer dereference in udf_expand_file_adinicbdue() during writeback (CVE-2022-0617)

  - kernel: swiotlb information leak with DMA_FROM_DEVICE (CVE-2022-0854)

  - kernel: uninitialized registers on stack in nft_do_chain can cause kernel pointer leakage to UM
    (CVE-2022-1016)

  - kernel: race condition in snd_pcm_hw_free leading to use-after-free (CVE-2022-1048)

  - kernel: use-after-free and memory errors in ext4 when mounting and operating on a corrupted image
    (CVE-2022-1184)

  - kernel: concurrency use-after-free between drm_setmaster_ioctl and drm_mode_getresources (CVE-2022-1280)

  - kernel: kernel info leak issue in pfkey_register (CVE-2022-1353)

  - kernel: use-after-free in ath9k_htc_probe_device() could cause an escalation of privileges (CVE-2022-1679)

  - kernel: NULL pointer dereference in x86_emulate_insn may lead to DoS (CVE-2022-1852)

  - kernel: fanotify misuses fd_install() which could lead to use-after-free (CVE-2022-1998)

  - kernel: net/packet: slab-out-of-bounds access in packet_recvmsg() (CVE-2022-20368)

  - hw: cpu: incomplete clean-up of multi-core shared buffers (aka SBDR) (CVE-2022-21123)

  - hw: cpu: incomplete clean-up of microarchitectural fill buffers (aka SBDS) (CVE-2022-21125)

  - hw: cpu: incomplete clean-up in specific special register write operations (aka DRPW) (CVE-2022-21166)

  - kernel: possible to use the debugger to write zero into a location of choice (CVE-2022-21499)

  - CVE-2022-29900 hw: cpu: AMD: RetBleed Arbitrary Speculative Code Execution with Return Instructions
    (CVE-2022-23816)

  - hw: cpu: AMD: Branch Type Confusion (non-retbleed) (CVE-2022-23825)

  - kernel: nfs_atomic_open() returns uninitialized data instead of ENOTDIR (CVE-2022-24448)

  - kernel: nf_tables cross-table potential use-after-free may lead to local privilege escalation
    (CVE-2022-2586)

  - hw: cpu: Intel: Post-barrier Return Stack Buffer Predictions (CVE-2022-26373)

  - kernel: openvswitch: integer underflow leads to out-of-bounds write in reserve_sfa_size() (CVE-2022-2639)

  - kernel: double free in ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c (CVE-2022-28390)

  - kernel: use after free in SUNRPC subsystem (CVE-2022-28893)

  - kernel: use-after-free due to improper update of reference count in net/sched/cls_u32.c (CVE-2022-29581)

  - CVE-2022-23816  hw: cpu: AMD: RetBleed Arbitrary Speculative Code Execution with Return Instructions
    (CVE-2022-29900)

  - hw: cpu: Intel: RetBleed Arbitrary Speculative Code Execution with Return Instructions (CVE-2022-29901)

  - kernel: DoS in nfqnl_mangle in net/netfilter/nfnetlink_queue.c (CVE-2022-36946)

  - kernel: nf_tables disallow binding to already bound chain (CVE-2022-39190)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-36516");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3640");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0168");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0617");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0854");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1048");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1280");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1353");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1679");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1852");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1998");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2586");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2639");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-20368");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21123");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21125");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21166");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21499");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23816");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23825");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24448");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-26373");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-28390");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-28893");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29581");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29900");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29901");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-36946");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-39190");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:7933");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1980646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2037386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2051444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2052312");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2053632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2058395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2059928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2066614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2066706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2066819");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2070205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2071022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2073064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2084125");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2084183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2084479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2088021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2089815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2090226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2090237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2090240");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2090241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2103148");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2103153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2114878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2123695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2129152");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29581");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(192, 200, 212, 267, 290, 362, 392, 401, 415, 416, 459, 476, 787, 824, 908);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2020-36516', 'CVE-2021-3640', 'CVE-2022-0168', 'CVE-2022-0617', 'CVE-2022-0854', 'CVE-2022-1016', 'CVE-2022-1048', 'CVE-2022-1184', 'CVE-2022-1280', 'CVE-2022-1353', 'CVE-2022-1679', 'CVE-2022-1852', 'CVE-2022-1998', 'CVE-2022-2586', 'CVE-2022-2639', 'CVE-2022-20368', 'CVE-2022-21123', 'CVE-2022-21125', 'CVE-2022-21166', 'CVE-2022-21499', 'CVE-2022-23816', 'CVE-2022-23825', 'CVE-2022-24448', 'CVE-2022-26373', 'CVE-2022-28390', 'CVE-2022-28893', 'CVE-2022-29581', 'CVE-2022-29900', 'CVE-2022-29901', 'CVE-2022-36946', 'CVE-2022-39190');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2022:7933');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9/x86_64/appstream/debug',
      'content/dist/rhel9/9/x86_64/appstream/os',
      'content/dist/rhel9/9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9/x86_64/baseos/debug',
      'content/dist/rhel9/9/x86_64/baseos/os',
      'content/dist/rhel9/9/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9/x86_64/codeready-builder/os',
      'content/dist/rhel9/9/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/x86_64/highavailability/debug',
      'content/dist/rhel9/9/x86_64/highavailability/os',
      'content/dist/rhel9/9/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel9/9/x86_64/nfv/debug',
      'content/dist/rhel9/9/x86_64/nfv/os',
      'content/dist/rhel9/9/x86_64/nfv/source/SRPMS',
      'content/dist/rhel9/9/x86_64/resilientstorage/debug',
      'content/dist/rhel9/9/x86_64/resilientstorage/os',
      'content/dist/rhel9/9/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel9/9/x86_64/rt/debug',
      'content/dist/rhel9/9/x86_64/rt/os',
      'content/dist/rhel9/9/x86_64/rt/source/SRPMS',
      'content/dist/rhel9/9/x86_64/sap-solutions/debug',
      'content/dist/rhel9/9/x86_64/sap-solutions/os',
      'content/dist/rhel9/9/x86_64/sap-solutions/source/SRPMS',
      'content/dist/rhel9/9/x86_64/sap/debug',
      'content/dist/rhel9/9/x86_64/sap/os',
      'content/dist/rhel9/9/x86_64/sap/source/SRPMS',
      'content/dist/rhel9/9/x86_64/supplementary/debug',
      'content/dist/rhel9/9/x86_64/supplementary/os',
      'content/dist/rhel9/9/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-5.14.0-162.6.1.rt21.168.el9_1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-core / kernel-rt-debug / kernel-rt-debug-core / etc');
}
