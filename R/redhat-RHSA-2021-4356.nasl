#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2021:4356. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155219);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id(
    "CVE-2019-14615",
    "CVE-2020-0427",
    "CVE-2020-24502",
    "CVE-2020-24503",
    "CVE-2020-24504",
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-26139",
    "CVE-2020-26140",
    "CVE-2020-26141",
    "CVE-2020-26143",
    "CVE-2020-26144",
    "CVE-2020-26145",
    "CVE-2020-26146",
    "CVE-2020-26147",
    "CVE-2020-27777",
    "CVE-2020-29368",
    "CVE-2020-29660",
    "CVE-2020-36158",
    "CVE-2020-36312",
    "CVE-2020-36386",
    "CVE-2021-0129",
    "CVE-2021-3348",
    "CVE-2021-3489",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-3600",
    "CVE-2021-3635",
    "CVE-2021-3659",
    "CVE-2021-3679",
    "CVE-2021-3732",
    "CVE-2021-20194",
    "CVE-2021-20239",
    "CVE-2021-23133",
    "CVE-2021-28950",
    "CVE-2021-28971",
    "CVE-2021-29155",
    "CVE-2021-29646",
    "CVE-2021-29650",
    "CVE-2021-31440",
    "CVE-2021-31829",
    "CVE-2021-31916",
    "CVE-2021-33033",
    "CVE-2021-33200"
  );
  script_xref(name:"RHSA", value:"2021:4356");
  script_xref(name:"IAVA", value:"2021-A-0223-S");
  script_xref(name:"IAVA", value:"2021-A-0222-S");

  script_name(english:"RHEL 8 : kernel (RHSA-2021:4356)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2021:4356 advisory.

  - kernel: Intel graphics card information leak. (CVE-2019-14615)

  - kernel: out-of-bounds reads in pinctrl subsystem. (CVE-2020-0427)

  - kernel: Improper input validation in some Intel(R) Ethernet E810 Adapter drivers (CVE-2020-24502)

  - kernel: Insufficient access control in some Intel(R) Ethernet E810 Adapter drivers (CVE-2020-24503)

  - kernel: Uncontrolled resource consumption in some Intel(R) Ethernet E810 Adapter drivers (CVE-2020-24504)

  - kernel: Fragmentation cache not cleared on reconnection (CVE-2020-24586)

  - kernel: Reassembling fragments encrypted under different keys (CVE-2020-24587)

  - kernel: wifi frame payload being parsed incorrectly as an L2 frame (CVE-2020-24588)

  - kernel: Forwarding EAPOL from unauthenticated wifi client (CVE-2020-26139)

  - kernel: accepting plaintext data frames in protected networks (CVE-2020-26140)

  - kernel: not verifying TKIP MIC of fragmented frames (CVE-2020-26141)

  - kernel: accepting fragmented plaintext frames in protected networks (CVE-2020-26143)

  - kernel: accepting unencrypted A-MSDU frames that start with RFC1042 header (CVE-2020-26144)

  - kernel: accepting plaintext broadcast fragments as full frames (CVE-2020-26145)

  - kernel: reassembling encrypted fragments with non-consecutive packet numbers (CVE-2020-26146)

  - kernel: reassembling mixed encrypted/plaintext fragments (CVE-2020-26147)

  - kernel: powerpc: RTAS calls can be used to compromise kernel integrity (CVE-2020-27777)

  - kernel: the copy-on-write implementation can grant unintended write access because of a race condition in
    a THP mapcount check (CVE-2020-29368)

  - kernel: locking inconsistency in drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c can lead to a read-
    after-free (CVE-2020-29660)

  - kernel: buffer overflow in mwifiex_cmd_802_11_ad_hoc_start function in
    drivers/net/wireless/marvell/mwifiex/join.c via a long SSID value (CVE-2020-36158)

  - kernel: memory leak upon a kmalloc failure in kvm_io_bus_unregister_dev function in virt/kvm/kvm_main.c
    (CVE-2020-36312)

  - kernel: slab out-of-bounds read in hci_extended_inquiry_result_evt() in net/bluetooth/hci_event.c
    (CVE-2020-36386)

  - kernel: Improper access control in BlueZ may allow information disclosure vulnerability. (CVE-2021-0129)

  - kernel: heap overflow in __cgroup_bpf_run_filter_getsockopt() (CVE-2021-20194)

  - kernel: setsockopt System Call Untrusted Pointer Dereference Information Disclosure (CVE-2021-20239)

  - kernel: Race condition in sctp_destroy_sock list_del (CVE-2021-23133)

  - kernel: fuse: stall on CPU can occur because a retry loop continually finds the same bad inode
    (CVE-2021-28950)

  - kernel: System crash in intel_pmu_drain_pebs_nhm in arch/x86/events/intel/ds.c (CVE-2021-28971)

  - kernel: protection for sequences of pointer arithmetic operations against speculatively out-of-bounds
    loads can be bypassed to leak content of kernel memory (CVE-2021-29155)

  - kernel: improper input validation in tipc_nl_retrieve_key function in net/tipc/node.c (CVE-2021-29646)

  - kernel: lack a full memory barrier upon the assignment of a new table value in net/netfilter/x_tables.c
    and include/linux/netfilter/x_tables.h may lead to DoS (CVE-2021-29650)

  - kernel: local escalation of privileges in handling of eBPF programs (CVE-2021-31440)

  - kernel: protection of stack pointer against speculative pointer arithmetic can be bypassed to leak content
    of kernel memory (CVE-2021-31829)

  - kernel: out of bounds array access in drivers/md/dm-ioctl.c (CVE-2021-31916)

  - kernel: use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c (CVE-2021-33033)

  - kernel: Improper input validation in the Intel(R) Ethernet ixgbe driver may allow an authenticated user to
    potentially enable DoS via local access (CVE-2021-33098)

  - kernel: out-of-bounds reads and writes due to enforcing incorrect limits for pointer arithmetic operations
    by BPF verifier (CVE-2021-33200)

  - kernel: Use-after-free in ndb_queue_rq() in drivers/block/nbd.c (CVE-2021-3348)

  - kernel: Linux kernel eBPF RINGBUF map oversized allocation (CVE-2021-3489)

  - kernel: double free in bluetooth subsystem when the HCI device initialization fails (CVE-2021-3564)

  - kernel: use-after-free in function hci_sock_bound_ioctl() (CVE-2021-3573)

  - kernel: eBPF 32-bit source register truncation on div/mod (CVE-2021-3600)

  - kernel: flowtable list del corruption with kernel BUG at lib/list_debug.c:50 (CVE-2021-3635)

  - kernel: NULL pointer dereference in llsec_key_alloc() in net/mac802154/llsec.c (CVE-2021-3659)

  - kernel: DoS in rb_per_cpu_empty() (CVE-2021-3679)

  - kernel: overlayfs: Mounting overlayfs inside an unprivileged user namespace can reveal files
    (CVE-2021-3732)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-14615");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-0427");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-24502");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-24503");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-24504");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-24586");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-24587");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-24588");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26139");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26140");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26141");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26143");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26144");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26145");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26146");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26147");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27777");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-29368");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-29660");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-36158");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-36312");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-36386");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-0129");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3348");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3489");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3564");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3573");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3600");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3635");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3659");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3679");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-3732");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-20194");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-20239");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-23133");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-28950");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-28971");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-29155");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-29646");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-29650");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-31440");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-31829");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-31916");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33033");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33098");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33200");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:4356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1789209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1900844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1903244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1906522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1912683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1913348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1919893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1921958");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1923636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1930381");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1941762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1941784");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1945345");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1945388");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1946965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1947991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1948772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1951595");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1957788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1959559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1959642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1959654");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1959657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1959663");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1960490");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1960492");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1960496");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1960498");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1960500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1960502");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1960504");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1961300");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1964028");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1964139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1965038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1965458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1966578");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1969489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1975949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1976946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1981954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1989165");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1995249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2068236");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3489");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 120, 125, 200, 212, 252, 287, 290, 307, 345, 346, 362, 400, 415, 416, 476, 662, 667, 682, 772, 787, 822, 829, 835, 862, 863);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_aus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_e4s:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_tus:8.6");
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
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  var cve_list = make_list('CVE-2019-14615', 'CVE-2020-0427', 'CVE-2020-24502', 'CVE-2020-24503', 'CVE-2020-24504', 'CVE-2020-24586', 'CVE-2020-24587', 'CVE-2020-24588', 'CVE-2020-26139', 'CVE-2020-26140', 'CVE-2020-26141', 'CVE-2020-26143', 'CVE-2020-26144', 'CVE-2020-26145', 'CVE-2020-26146', 'CVE-2020-26147', 'CVE-2020-27777', 'CVE-2020-29368', 'CVE-2020-29660', 'CVE-2020-36158', 'CVE-2020-36312', 'CVE-2020-36386', 'CVE-2021-0129', 'CVE-2021-3348', 'CVE-2021-3489', 'CVE-2021-3564', 'CVE-2021-3573', 'CVE-2021-3600', 'CVE-2021-3635', 'CVE-2021-3659', 'CVE-2021-3679', 'CVE-2021-3732', 'CVE-2021-20194', 'CVE-2021-20239', 'CVE-2021-23133', 'CVE-2021-28950', 'CVE-2021-28971', 'CVE-2021-29155', 'CVE-2021-29646', 'CVE-2021-29650', 'CVE-2021-31440', 'CVE-2021-31829', 'CVE-2021-31916', 'CVE-2021-33033', 'CVE-2021-33098', 'CVE-2021-33200');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for RHSA-2021:4356');
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
      'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
      'content/e4s/rhel8/8.6/ppc64le/appstream/os',
      'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/baseos/debug',
      'content/e4s/rhel8/8.6/ppc64le/baseos/os',
      'content/e4s/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/debug',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/os',
      'content/e4s/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/e4s/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/e4s/rhel8/8.6/ppc64le/sap/debug',
      'content/e4s/rhel8/8.6/ppc64le/sap/os',
      'content/e4s/rhel8/8.6/ppc64le/sap/source/SRPMS',
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
      'content/eus/rhel8/8.6/aarch64/appstream/debug',
      'content/eus/rhel8/8.6/aarch64/appstream/os',
      'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/baseos/debug',
      'content/eus/rhel8/8.6/aarch64/baseos/os',
      'content/eus/rhel8/8.6/aarch64/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/debug',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/os',
      'content/eus/rhel8/8.6/aarch64/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/highavailability/debug',
      'content/eus/rhel8/8.6/aarch64/highavailability/os',
      'content/eus/rhel8/8.6/aarch64/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/aarch64/supplementary/debug',
      'content/eus/rhel8/8.6/aarch64/supplementary/os',
      'content/eus/rhel8/8.6/aarch64/supplementary/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/appstream/debug',
      'content/eus/rhel8/8.6/ppc64le/appstream/os',
      'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/baseos/debug',
      'content/eus/rhel8/8.6/ppc64le/baseos/os',
      'content/eus/rhel8/8.6/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/debug',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/os',
      'content/eus/rhel8/8.6/ppc64le/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/highavailability/debug',
      'content/eus/rhel8/8.6/ppc64le/highavailability/os',
      'content/eus/rhel8/8.6/ppc64le/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/debug',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/os',
      'content/eus/rhel8/8.6/ppc64le/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/debug',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/os',
      'content/eus/rhel8/8.6/ppc64le/sap-solutions/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/sap/debug',
      'content/eus/rhel8/8.6/ppc64le/sap/os',
      'content/eus/rhel8/8.6/ppc64le/sap/source/SRPMS',
      'content/eus/rhel8/8.6/ppc64le/supplementary/debug',
      'content/eus/rhel8/8.6/ppc64le/supplementary/os',
      'content/eus/rhel8/8.6/ppc64le/supplementary/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/appstream/debug',
      'content/eus/rhel8/8.6/s390x/appstream/os',
      'content/eus/rhel8/8.6/s390x/appstream/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/baseos/debug',
      'content/eus/rhel8/8.6/s390x/baseos/os',
      'content/eus/rhel8/8.6/s390x/baseos/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/codeready-builder/debug',
      'content/eus/rhel8/8.6/s390x/codeready-builder/os',
      'content/eus/rhel8/8.6/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/highavailability/debug',
      'content/eus/rhel8/8.6/s390x/highavailability/os',
      'content/eus/rhel8/8.6/s390x/highavailability/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/resilientstorage/debug',
      'content/eus/rhel8/8.6/s390x/resilientstorage/os',
      'content/eus/rhel8/8.6/s390x/resilientstorage/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/sap/debug',
      'content/eus/rhel8/8.6/s390x/sap/os',
      'content/eus/rhel8/8.6/s390x/sap/source/SRPMS',
      'content/eus/rhel8/8.6/s390x/supplementary/debug',
      'content/eus/rhel8/8.6/s390x/supplementary/os',
      'content/eus/rhel8/8.6/s390x/supplementary/source/SRPMS',
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
      {'reference':'bpftool-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-stablelists-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-348.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-348.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-348.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-348.el8', 'sp':'6', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-348.el8', 'sp':'6', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-348.el8', 'sp':'6', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-348.el8', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-348.el8', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-348.el8', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-348.el8', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-348.el8', 'sp':'6', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-348.el8', 'sp':'6', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
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
      {'reference':'bpftool-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-abi-stablelists-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-core-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-cross-headers-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-core-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-devel-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-debug-modules-extra-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-devel-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-headers-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-modules-extra-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-348.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-348.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-348.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-tools-libs-devel-4.18.0-348.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-4.18.0-348.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-core-4.18.0-348.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-devel-4.18.0-348.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-4.18.0-348.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'kernel-zfcpdump-modules-extra-4.18.0-348.el8', 'cpu':'s390x', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perf-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-perf-4.18.0-348.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bpftool / kernel / kernel-abi-stablelists / kernel-core / etc');
}
