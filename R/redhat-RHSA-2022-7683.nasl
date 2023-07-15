#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:7683. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167155);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2020-36516",
    "CVE-2020-36558",
    "CVE-2021-3640",
    "CVE-2021-30002",
    "CVE-2022-0168",
    "CVE-2022-0617",
    "CVE-2022-0854",
    "CVE-2022-1016",
    "CVE-2022-1048",
    "CVE-2022-1055",
    "CVE-2022-1184",
    "CVE-2022-1852",
    "CVE-2022-2078",
    "CVE-2022-2586",
    "CVE-2022-2639",
    "CVE-2022-2938",
    "CVE-2022-20368",
    "CVE-2022-21499",
    "CVE-2022-23960",
    "CVE-2022-24448",
    "CVE-2022-26373",
    "CVE-2022-27950",
    "CVE-2022-28390",
    "CVE-2022-28893",
    "CVE-2022-29581",
    "CVE-2022-36946"
  );
  script_xref(name:"RHSA", value:"2022:7683");

  script_name(english:"RHEL 8 : kernel (RHSA-2022:7683)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:7683 advisory.

  - kernel: off-path attacker may inject data or terminate victim's TCP session (CVE-2020-36516)

  - kernel: race condition in VT_RESIZEX ioctl when vc_cons[i].d is already NULL leading to NULL pointer
    dereference (CVE-2020-36558)

  - kernel: memory leak for large arguments in video_usercopy function in drivers/media/v4l2-core/v4l2-ioctl.c
    (CVE-2021-30002)

  - kernel: use-after-free vulnerability in function sco_sock_sendmsg() (CVE-2021-3640)

  - kernel: smb2_ioctl_query_info NULL pointer dereference (CVE-2022-0168)

  - kernel: NULL pointer dereference in udf_expand_file_adinicbdue() during writeback (CVE-2022-0617)

  - kernel: swiotlb information leak with DMA_FROM_DEVICE (CVE-2022-0854)

  - kernel: uninitialized registers on stack in nft_do_chain can cause kernel pointer leakage to UM
    (CVE-2022-1016)

  - kernel: race condition in snd_pcm_hw_free leading to use-after-free (CVE-2022-1048)

  - kernel: use-after-free in tc_new_tfilter() in net/sched/cls_api.c (CVE-2022-1055)

  - kernel: KVM: cmpxchg_gpte can write to pfns outside the userspace region (CVE-2022-1158)

  - kernel: use-after-free and memory errors in ext4 when mounting and operating on a corrupted image
    (CVE-2022-1184)

  - kernel: NULL pointer dereference in x86_emulate_insn may lead to DoS (CVE-2022-1852)

  - kernel: net/packet: slab-out-of-bounds access in packet_recvmsg() (CVE-2022-20368)

  - kernel: buffer overflow in nft_set_desc_concat_parse() (CVE-2022-2078)

  - kernel: possible to use the debugger to write zero into a location of choice (CVE-2022-21499)

  - hw: cpu: arm64: Spectre-BHB (CVE-2022-23960)

  - kernel: nfs_atomic_open() returns uninitialized data instead of ENOTDIR (CVE-2022-24448)

  - kernel: nf_tables cross-table potential use-after-free may lead to local privilege escalation
    (CVE-2022-2586)

  - hw: cpu: Intel: Post-barrier Return Stack Buffer Predictions (CVE-2022-26373)

  - kernel: openvswitch: integer underflow leads to out-of-bounds write in reserve_sfa_size() (CVE-2022-2639)

  - kernel: memory leak in drivers/hid/hid-elo.c (CVE-2022-27950)

  - kernel: double free in ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c (CVE-2022-28390)

  - kernel: use after free in SUNRPC subsystem (CVE-2022-28893)

  - kernel: use-after-free when psi trigger is destroyed while being polled (CVE-2022-2938)

  - kernel: use-after-free due to improper update of reference count in net/sched/cls_u32.c (CVE-2022-29581)

  - kernel: DoS in nfqnl_mangle in net/netfilter/nfnetlink_queue.c (CVE-2022-36946)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-36516");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-36558");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3640");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30002");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0168");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0617");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0854");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1048");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1055");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1158");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1852");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2078");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2586");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2639");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2938");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-20368");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-21499");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-23960");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-24448");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-26373");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27950");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-28390");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-28893");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-29581");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-36946");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:7683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1946279");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1980646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2037386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2051444");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2053632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2058395");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2059928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2062284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2066614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2066706");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2069408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2069793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2070205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2070220");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2073064");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2074208");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2084183");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2084479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2088021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2089815");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2096178");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2112693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2114878");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115065");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2115278");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2120175");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2123695");
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
  script_cwe_id(120, 192, 200, 267, 290, 362, 401, 415, 416, 476, 772, 787, 824, 908);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-stablelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-cross-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-zfcpdump-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-perf");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2020-36516', 'CVE-2020-36558', 'CVE-2021-3640', 'CVE-2021-30002', 'CVE-2022-0168', 'CVE-2022-0617', 'CVE-2022-0854', 'CVE-2022-1016', 'CVE-2022-1048', 'CVE-2022-1055', 'CVE-2022-1158', 'CVE-2022-1184', 'CVE-2022-1852', 'CVE-2022-2078', 'CVE-2022-2586', 'CVE-2022-2639', 'CVE-2022-2938', 'CVE-2022-20368', 'CVE-2022-21499', 'CVE-2022-23960', 'CVE-2022-24448', 'CVE-2022-26373', 'CVE-2022-27950', 'CVE-2022-28390', 'CVE-2022-28893', 'CVE-2022-29581', 'CVE-2022-36946');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2022:7683');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel8/8/aarch64/appstream/debug',
      'content/dist/rhel8/8/aarch64/appstream/os',
      'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
      'content/dist/rhel8/8/aarch64/baseos/debug',
      'content/dist/rhel8/8/aarch64/baseos/os',
      'content/dist/rhel8/8/aarch64/baseos/source/SRPMS',
      'content/dist/rhel8/8/aarch64/codeready-builder/debug',
      'content/dist/rhel8/8/aarch64/codeready-builder/os',
      'content/dist/rhel8/8/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/aarch64/highavailability/debug',
      'content/dist/rhel8/8/aarch64/highavailability/os',
      'content/dist/rhel8/8/aarch64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/aarch64/supplementary/debug',
      'content/dist/rhel8/8/aarch64/supplementary/os',
      'content/dist/rhel8/8/aarch64/supplementary/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/appstream/debug',
      'content/dist/rhel8/8/ppc64le/appstream/os',
      'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/baseos/debug',
      'content/dist/rhel8/8/ppc64le/baseos/os',
      'content/dist/rhel8/8/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/codeready-builder/debug',
      'content/dist/rhel8/8/ppc64le/codeready-builder/os',
      'content/dist/rhel8/8/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/highavailability/debug',
      'content/dist/rhel8/8/ppc64le/highavailability/os',
      'content/dist/rhel8/8/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/resilientstorage/debug',
      'content/dist/rhel8/8/ppc64le/resilientstorage/os',
      'content/dist/rhel8/8/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap-solutions/debug',
      'content/dist/rhel8/8/ppc64le/sap-solutions/os',
      'content/dist/rhel8/8/ppc64le/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/sap/debug',
      'content/dist/rhel8/8/ppc64le/sap/os',
      'content/dist/rhel8/8/ppc64le/sap/source/SRPMS',
      'content/dist/rhel8/8/ppc64le/supplementary/debug',
      'content/dist/rhel8/8/ppc64le/supplementary/os',
      'content/dist/rhel8/8/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel8/8/s390x/appstream/debug',
      'content/dist/rhel8/8/s390x/appstream/os',
      'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
      'content/dist/rhel8/8/s390x/baseos/debug',
      'content/dist/rhel8/8/s390x/baseos/os',
      'content/dist/rhel8/8/s390x/baseos/source/SRPMS',
      'content/dist/rhel8/8/s390x/codeready-builder/debug',
      'content/dist/rhel8/8/s390x/codeready-builder/os',
      'content/dist/rhel8/8/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/s390x/highavailability/debug',
      'content/dist/rhel8/8/s390x/highavailability/os',
      'content/dist/rhel8/8/s390x/highavailability/source/SRPMS',
      'content/dist/rhel8/8/s390x/resilientstorage/debug',
      'content/dist/rhel8/8/s390x/resilientstorage/os',
      'content/dist/rhel8/8/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/s390x/sap/debug',
      'content/dist/rhel8/8/s390x/sap/os',
      'content/dist/rhel8/8/s390x/sap/source/SRPMS',
      'content/dist/rhel8/8/s390x/supplementary/debug',
      'content/dist/rhel8/8/s390x/supplementary/os',
      'content/dist/rhel8/8/s390x/supplementary/source/SRPMS',
      'content/dist/rhel8/8/x86_64/appstream/debug',
      'content/dist/rhel8/8/x86_64/appstream/os',
      'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
      'content/dist/rhel8/8/x86_64/baseos/debug',
      'content/dist/rhel8/8/x86_64/baseos/os',
      'content/dist/rhel8/8/x86_64/baseos/source/SRPMS',
      'content/dist/rhel8/8/x86_64/codeready-builder/debug',
      'content/dist/rhel8/8/x86_64/codeready-builder/os',
      'content/dist/rhel8/8/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel8/8/x86_64/highavailability/debug',
      'content/dist/rhel8/8/x86_64/highavailability/os',
      'content/dist/rhel8/8/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel8/8/x86_64/nfv/debug',
      'content/dist/rhel8/8/x86_64/nfv/os',
      'content/dist/rhel8/8/x86_64/nfv/source/SRPMS',
      'content/dist/rhel8/8/x86_64/resilientstorage/debug',
      'content/dist/rhel8/8/x86_64/resilientstorage/os',
      'content/dist/rhel8/8/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel8/8/x86_64/rt/debug',
      'content/dist/rhel8/8/x86_64/rt/os',
      'content/dist/rhel8/8/x86_64/rt/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap-solutions/debug',
      'content/dist/rhel8/8/x86_64/sap-solutions/os',
      'content/dist/rhel8/8/x86_64/sap-solutions/source/SRPMS',
      'content/dist/rhel8/8/x86_64/sap/debug',
      'content/dist/rhel8/8/x86_64/sap/os',
      'content/dist/rhel8/8/x86_64/sap/source/SRPMS',
      'content/dist/rhel8/8/x86_64/supplementary/debug',
      'content/dist/rhel8/8/x86_64/supplementary/os',
      'content/dist/rhel8/8/x86_64/supplementary/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'bpftool-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-stablelists-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-425.3.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-425.3.1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-425.3.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-425.3.1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-425.3.1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-425.3.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-425.3.1.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-425.3.1.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-425.3.1.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-425.3.1.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-425.3.1.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-425.3.1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / kernel-core / etc');
}
