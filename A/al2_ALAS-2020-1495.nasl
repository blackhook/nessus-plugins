#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1495.
#

include('compat.inc');

if (description)
{
  script_id(141106);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2019-19448",
    "CVE-2020-14314",
    "CVE-2020-14331",
    "CVE-2020-25211",
    "CVE-2020-25212",
    "CVE-2020-25285"
  );
  script_xref(name:"ALAS", value:"2020-1495");

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2020-1495)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1495 advisory.

  - In the Linux kernel 5.0.21 and 5.3.11, mounting a crafted btrfs filesystem image, performing some
    operations, and then making a syncfs system call can lead to a use-after-free in try_merge_free_space in
    fs/btrfs/free-space-cache.c because the pointer to a left data structure can be the same as the pointer to
    a right data structure. (CVE-2019-19448)

  - A memory out-of-bounds read flaw was found in the Linux kernel before 5.9-rc2 with the ext3/ext4 file
    system, in the way it accesses a directory with broken indexing. This flaw allows a local user to crash
    the system if the directory exists. The highest threat from this vulnerability is to system availability.
    (CVE-2020-14314)

  - A flaw was found in the Linux kernels implementation of the invert video code on VGA consoles when a
    local attacker attempts to resize the console, calling an ioctl VT_RESIZE, which causes an out-of-bounds
    write to occur. This flaw allows a local user with access to the VGA console to crash the system,
    potentially escalating their privileges on the system. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2020-14331)

  - In the Linux kernel through 5.8.7, local attackers able to inject conntrack netlink configuration could
    overflow a local buffer, causing crashes or triggering use of incorrect protocol numbers in
    ctnetlink_parse_tuple_filter in net/netfilter/nf_conntrack_netlink.c, aka CID-1cc5ef91d2ff.
    (CVE-2020-25211)

  - A TOCTOU mismatch in the NFS client code in the Linux kernel before 5.8.3 could be used by local attackers
    to corrupt memory or possibly have unspecified other impact because a size check is in fs/nfs/nfs4proc.c
    instead of fs/nfs/nfs4xdr.c, aka CID-b4487b935452. (CVE-2020-25212)

  - A race condition between hugetlb sysctl handlers in mm/hugetlb.c in the Linux kernel before 5.8.8 could be
    used by local attackers to corrupt memory, cause a NULL pointer dereference, or possibly have unspecified
    other impact, aka CID-17743798d812. (CVE-2020-25285)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1495.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19448");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14314");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-14331");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25211");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25212");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-25285");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14331");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-19448");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-4.14.198-152.320");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (get_one_kb_item("Host/kpatch/kernel-cves"))
{
  set_hotfix_type("kpatch");
  cve_list = make_list("CVE-2019-19448", "CVE-2020-14314", "CVE-2020-14331", "CVE-2020-25211", "CVE-2020-25212", "CVE-2020-25285");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2020-1495");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}
pkgs = [
    {'reference':'kernel-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-common-aarch64-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-common-x86_64-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-devel-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-devel-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.198-152.320.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-livepatch-4.14.198-152.320-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-debuginfo-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-debuginfo-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-devel-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-devel-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perf-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perf-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perf-debuginfo-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perf-debuginfo-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python-perf-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python-perf-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python-perf-debuginfo-4.14.198-152.320.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python-perf-debuginfo-4.14.198-152.320.amzn2', 'cpu':'x86_64', 'release':'AL2'}
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