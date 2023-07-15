##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:1975. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161034);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id(
    "CVE-2020-0404",
    "CVE-2020-13974",
    "CVE-2020-27820",
    "CVE-2021-0941",
    "CVE-2021-3612",
    "CVE-2021-3669",
    "CVE-2021-3743",
    "CVE-2021-3744",
    "CVE-2021-3752",
    "CVE-2021-3759",
    "CVE-2021-3764",
    "CVE-2021-3772",
    "CVE-2021-3773",
    "CVE-2021-4002",
    "CVE-2021-4037",
    "CVE-2021-4083",
    "CVE-2021-4157",
    "CVE-2021-4197",
    "CVE-2021-4203",
    "CVE-2021-20322",
    "CVE-2021-26401",
    "CVE-2021-29154",
    "CVE-2021-37159",
    "CVE-2021-41864",
    "CVE-2021-42739",
    "CVE-2021-43389",
    "CVE-2021-43976",
    "CVE-2021-44733",
    "CVE-2021-45485",
    "CVE-2021-45486",
    "CVE-2022-0001",
    "CVE-2022-0002",
    "CVE-2022-0286",
    "CVE-2022-0322",
    "CVE-2022-1011"
  );
  script_xref(name:"RHSA", value:"2022:1975");

  script_name(english:"RHEL 8 : kernel-rt (RHSA-2022:1975)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:1975 advisory.

  - kernel: avoid cyclic entity chains due to malformed USB descriptors (CVE-2020-0404)

  - kernel: integer overflow in k_ascii() in drivers/tty/vt/keyboard.c (CVE-2020-13974)

  - kernel: use-after-free in nouveau kernel module (CVE-2020-27820)

  - kernel: out-of-bounds read in bpf_skb_change_head() of filter.c due to a use-after-free (CVE-2021-0941)

  - kernel: new DNS Cache Poisoning Attack based on ICMP fragment needed packets replies (CVE-2021-20322)

  - hw: cpu: LFENCE/JMP Mitigation Update for CVE-2017-5715 (CVE-2021-26401)

  - kernel: Local privilege escalation due to incorrect BPF JIT branch displacement computation
    (CVE-2021-29154)

  - kernel: joydev: zero size passed to joydev_handle_JSIOCSBTNMAP() (CVE-2021-3612)

  - kernel: reading /proc/sysvipc/shm does not scale with large shared memory segment counts (CVE-2021-3669)

  - kernel: use-after-free in hso_free_net_device() in drivers/net/usb/hso.c (CVE-2021-37159)

  - kernel: out-of-bound Read in qrtr_endpoint_post in net/qrtr/qrtr.c (CVE-2021-3743)

  - kernel: crypto: ccp - fix resource leaks in ccp_run_aes_gcm_cmd() (CVE-2021-3744)

  - kernel: possible use-after-free in bluetooth module (CVE-2021-3752)

  - kernel: unaccounted ipc objects in Linux kernel lead to breaking memcg limits and DoS attacks
    (CVE-2021-3759)

  - kernel: DoS in ccp_run_aes_gcm_cmd() function (CVE-2021-3764)

  - kernel: sctp: Invalid chunks may be used to remotely remove existing associations (CVE-2021-3772)

  - kernel: lack of port sanity checking in natd and netfilter leads to exploit of OpenVPN clients
    (CVE-2021-3773)

  - kernel: possible leak or coruption of data residing on hugetlbfs (CVE-2021-4002)

  - kernel: security regression for CVE-2018-13405 (CVE-2021-4037)

  - kernel: fget: check that the fd still exists after getting a ref to it (CVE-2021-4083)

  - kernel: Buffer overwrite in decode_nfs_fh function (CVE-2021-4157)

  - kernel: eBPF multiplication integer overflow in prealloc_elems_and_freelist() in kernel/bpf/stackmap.c
    leads to out-of-bounds write (CVE-2021-41864)

  - kernel: cgroup: Use open-time creds and namespace for migration perm checks (CVE-2021-4197)

  - kernel: Race condition in races in sk_peer_pid and sk_peer_cred accesses (CVE-2021-4203)

  - kernel: Heap buffer overflow in firedtv driver (CVE-2021-42739)

  - kernel: an array-index-out-bounds in detach_capi_ctr in drivers/isdn/capi/kcapi.c (CVE-2021-43389)

  - kernel: mwifiex_usb_recv() in drivers/net/wireless/marvell/mwifiex/usb.c allows an attacker to cause DoS
    via crafted USB device (CVE-2021-43976)

  - kernel: use-after-free in the TEE subsystem (CVE-2021-44733)

  - kernel: information leak in the IPv6 implementation (CVE-2021-45485)

  - kernel: information leak in the IPv4 implementation (CVE-2021-45486)

  - hw: cpu: intel: Branch History Injection (BHI) (CVE-2022-0001)

  - hw: cpu: intel: Intra-Mode BTI (CVE-2022-0002)

  - kernel: Local denial of service in bond_ipsec_add_sa (CVE-2022-0286)

  - kernel: DoS in sctp_addto_chunk in net/sctp/sm_make_chunk.c (CVE-2022-0322)

  - kernel: FUSE allows UAF reads of write() buffers, allowing theft of (partial) /etc/shadow hashes
    (CVE-2022-1011)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-0404");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-13974");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27820");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-0941");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3612");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3669");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3743");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3744");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3752");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3759");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3764");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3772");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3773");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-4002");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-4037");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-4083");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-4157");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-4197");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-4203");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-20322");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-26401");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-29154");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-37159");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-41864");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-42739");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-43389");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-43976");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-44733");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-45485");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-45486");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0001");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0002");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0286");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-0322");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-1011");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:1975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1901726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1919791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1946684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1974079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1985353");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1997467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1997961");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1999544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1999675");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2000627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2000694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2004949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2010463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2013180");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2014230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2016169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2018205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2025003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2025726");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2027239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2029923");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2030747");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2034342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2035652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2036934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2037019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2039911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2039914");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2042822");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2061700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2061712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2061721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2064855");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3752");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3773");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 125, 129, 190, 200, 284, 287, 327, 330, 354, 362, 400, 401, 416, 459, 476, 681, 787, 908);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2020-0404', 'CVE-2020-13974', 'CVE-2020-27820', 'CVE-2021-0941', 'CVE-2021-3612', 'CVE-2021-3669', 'CVE-2021-3743', 'CVE-2021-3744', 'CVE-2021-3752', 'CVE-2021-3759', 'CVE-2021-3764', 'CVE-2021-3772', 'CVE-2021-3773', 'CVE-2021-4002', 'CVE-2021-4037', 'CVE-2021-4083', 'CVE-2021-4157', 'CVE-2021-4197', 'CVE-2021-4203', 'CVE-2021-20322', 'CVE-2021-26401', 'CVE-2021-29154', 'CVE-2021-37159', 'CVE-2021-41864', 'CVE-2021-42739', 'CVE-2021-43389', 'CVE-2021-43976', 'CVE-2021-44733', 'CVE-2021-45485', 'CVE-2021-45486', 'CVE-2022-0001', 'CVE-2022-0002', 'CVE-2022-0286', 'CVE-2022-0322', 'CVE-2022-1011');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2022:1975');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel8/8.6/x86_64/appstream/debug',
      'content/aus/rhel8/8.6/x86_64/appstream/os',
      'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/aus/rhel8/8.6/x86_64/baseos/debug',
      'content/aus/rhel8/8.6/x86_64/baseos/os',
      'content/aus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/appstream/debug',
      'content/e4s/rhel8/8.6/x86_64/appstream/os',
      'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/baseos/debug',
      'content/e4s/rhel8/8.6/x86_64/baseos/os',
      'content/e4s/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/highavailability/debug',
      'content/e4s/rhel8/8.6/x86_64/highavailability/os',
      'content/e4s/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/os',
      'content/e4s/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/x86_64/sap/debug',
      'content/e4s/rhel8/8.6/x86_64/sap/os',
      'content/e4s/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/appstream/debug',
      'content/eus/rhel8/8.6/x86_64/appstream/os',
      'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/baseos/debug',
      'content/eus/rhel8/8.6/x86_64/baseos/os',
      'content/eus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/debug',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/os',
      'content/eus/rhel8/8.6/x86_64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/highavailability/debug',
      'content/eus/rhel8/8.6/x86_64/highavailability/os',
      'content/eus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/debug',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/os',
      'content/eus/rhel8/8.6/x86_64/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/debug',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/os',
      'content/eus/rhel8/8.6/x86_64/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/sap/debug',
      'content/eus/rhel8/8.6/x86_64/sap/os',
      'content/eus/rhel8/8.6/x86_64/sap/source/SRPMS',
      'content/eus/rhel8/8.6/x86_64/supplementary/debug',
      'content/eus/rhel8/8.6/x86_64/supplementary/os',
      'content/eus/rhel8/8.6/x86_64/supplementary/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/appstream/debug',
      'content/tus/rhel8/8.6/x86_64/appstream/os',
      'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/baseos/debug',
      'content/tus/rhel8/8.6/x86_64/baseos/os',
      'content/tus/rhel8/8.6/x86_64/baseos/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/highavailability/debug',
      'content/tus/rhel8/8.6/x86_64/highavailability/os',
      'content/tus/rhel8/8.6/x86_64/highavailability/source/SRPMS',
      'content/tus/rhel8/8.6/x86_64/rt/os',
      'content/tus/rhel8/8.6/x86_64/rt/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'kernel-rt-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-372.9.1.rt7.166.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
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
      {'reference':'kernel-rt-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-core-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-core-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-devel-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-kvm-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-debug-modules-extra-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-devel-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-kvm-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-rt-modules-extra-4.18.0-372.9.1.rt7.166.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  var enterprise_linux_flag = rhel_repo_urls_has_content_dist_rhel(repo_urls:repo_relative_urls);
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
    if (!empty_or_null(pkg['sp']) && !enterprise_linux_flag) sp = pkg['sp'];
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
