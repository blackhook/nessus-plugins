#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2021-1503.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149872);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/24");

  script_cve_id(
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-25672",
    "CVE-2020-25673",
    "CVE-2020-29374",
    "CVE-2021-23133",
    "CVE-2021-28688",
    "CVE-2021-28964",
    "CVE-2021-28971",
    "CVE-2021-29154",
    "CVE-2021-29155",
    "CVE-2021-31829",
    "CVE-2021-31916",
    "CVE-2021-33033"
  );
  script_xref(name:"ALAS", value:"2021-1503");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2021-1503)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 4.14.232-123.381. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS-2021-1503 advisory.

  - An issue was discovered in the Linux kernel before 5.7.3, related to mm/gup.c and mm/huge_memory.c. The
    get_user_pages (aka gup) implementation, when used for a copy-on-write page, does not properly consider
    the semantics of read operations and therefore can grant unintended write access, aka CID-17839856fd58.
    (CVE-2020-29374)

  - A race condition in Linux kernel SCTP sockets (net/sctp/socket.c) before 5.12-rc8 can lead to kernel
    privilege escalation from the context of a network service or an unprivileged process. If
    sctp_destroy_sock is called without sock_net(sk)->sctp.addr_wq_lock then an element is removed from the
    auto_asconf_splist list without any proper locking. This can be exploited by an attacker with network
    service privileges to escalate to root or from the context of an unprivileged user directly if a
    BPF_CGROUP_INET_SOCK_CREATE is attached which denies creation of some SCTP socket. (CVE-2021-23133)

  - The fix for XSA-365 includes initialization of pointers such that subsequent cleanup code wouldn't use
    uninitialized or stale values. This initialization went too far and may under certain conditions also
    overwrite pointers which are in need of cleaning up. The lack of cleanup would result in leaking
    persistent grants. The leak in turn would prevent fully cleaning up after a respective guest has died,
    leaving around zombie domains. All Linux versions having the fix for XSA-365 applied are vulnerable.
    XSA-365 was classified to affect versions back to at least 3.11. (CVE-2021-28688)

  - A race condition was discovered in get_old_root in fs/btrfs/ctree.c in the Linux kernel through 5.11.8. It
    allows attackers to cause a denial of service (BUG) because of a lack of locking on an extent buffer
    before a cloning operation, aka CID-dbcc7d57bffc. (CVE-2021-28964)

  - In intel_pmu_drain_pebs_nhm in arch/x86/events/intel/ds.c in the Linux kernel through 5.11.8 on some
    Haswell CPUs, userspace applications (such as perf-fuzzer) can cause a system crash because the PEBS
    status in a PEBS record is mishandled, aka CID-d88d05a9e0b6. (CVE-2021-28971)

  - BPF JIT compilers in the Linux kernel through 5.11.12 have incorrect computation of branch displacements,
    allowing them to execute arbitrary code within the kernel context. This affects
    arch/x86/net/bpf_jit_comp.c and arch/x86/net/bpf_jit_comp32.c. (CVE-2021-29154)

  - An issue was discovered in the Linux kernel through 5.11.x. kernel/bpf/verifier.c performs undesirable
    out-of-bounds speculation on pointer arithmetic, leading to side-channel attacks that defeat Spectre
    mitigations and obtain sensitive information from kernel memory. Specifically, for sequences of pointer
    arithmetic operations, the pointer modification performed by the first operation is not correctly
    accounted for when restricting subsequent operations. (CVE-2021-29155)

  - kernel/bpf/verifier.c in the Linux kernel through 5.12.1 performs undesirable speculative loads, leading
    to disclosure of stack content via side-channel attacks, aka CID-801c6058d14a. The specific concern is not
    protecting the BPF stack area against speculative loads. Also, the BPF stack can contain uninitialized
    data that might represent sensitive information previously operated on by the kernel. (CVE-2021-31829)

  - An out-of-bounds (OOB) memory write flaw was found in list_devices in drivers/md/dm-ioctl.c in the Multi-
    device driver module in the Linux kernel before 5.12. A bound check failure allows an attacker with
    special user (CAP_SYS_ADMIN) privilege to gain access to out-of-bounds memory leading to a system crash or
    a leak of internal kernel information. The highest threat from this vulnerability is to system
    availability. (CVE-2021-31916)

  - The Linux kernel before 5.11.14 has a use-after-free in cipso_v4_genopt in net/ipv4/cipso_ipv4.c because
    the CIPSO and CALIPSO refcounting for the DOI definitions is mishandled, aka CID-ad5d07f4a9cd. This leads
    to writing an arbitrary value. (CVE-2021-33033)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2021-1503.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25670");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25671");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25672");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25673");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-29374");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-23133");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-28688");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-28964");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-28971");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-29154");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-29155");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-31829");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-31916");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-33033");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29154");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("hotfixes.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  cve_list = make_list("CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2020-29374", "CVE-2021-23133", "CVE-2021-28688", "CVE-2021-28964", "CVE-2021-28971", "CVE-2021-29154", "CVE-2021-29155", "CVE-2021-31829", "CVE-2021-31916", "CVE-2021-33033");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2021-1503");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}
pkgs = [
    {'reference':'kernel-4.14.232-123.381.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-4.14.232-123.381.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-4.14.232-123.381.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-4.14.232-123.381.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-i686-4.14.232-123.381.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-debuginfo-common-x86_64-4.14.232-123.381.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.232-123.381.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-devel-4.14.232-123.381.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.232-123.381.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-headers-4.14.232-123.381.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.232-123.381.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-4.14.232-123.381.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-4.14.232-123.381.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-debuginfo-4.14.232-123.381.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-4.14.232-123.381.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-tools-devel-4.14.232-123.381.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.232-123.381.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-4.14.232-123.381.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-4.14.232-123.381.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-debuginfo-4.14.232-123.381.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-x86_64 / etc");
}