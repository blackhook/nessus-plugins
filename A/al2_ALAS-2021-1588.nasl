##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1588.
##

include('compat.inc');

if (description)
{
  script_id(145456);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2019-19813",
    "CVE-2019-19816",
    "CVE-2020-27815",
    "CVE-2020-29568",
    "CVE-2020-29569",
    "CVE-2020-29660",
    "CVE-2020-29661"
  );
  script_xref(name:"ALAS", value:"2021-1588");

  script_name(english:"Amazon Linux 2 : kernel (ALAS-2021-1588)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of kernel installed on the remote host is prior to 4.14.214-160.339. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2021-1588 advisory.

  - In the Linux kernel 5.0.21, mounting a crafted btrfs filesystem image, performing some operations, and
    then making a syncfs system call can lead to a use-after-free in __mutex_lock in kernel/locking/mutex.c.
    This is related to mutex_can_spin_on_owner in kernel/locking/mutex.c, __btrfs_qgroup_free_meta in
    fs/btrfs/qgroup.c, and btrfs_insert_delayed_items in fs/btrfs/delayed-inode.c. (CVE-2019-19813)

  - In the Linux kernel 5.0.21, mounting a crafted btrfs filesystem image and performing some operations can
    cause slab-out-of-bounds write access in __btrfs_map_block in fs/btrfs/volumes.c, because a value of 1 for
    the number of data stripes is mishandled. (CVE-2019-19816)

  - An issue was discovered in Xen through 4.14.x. Some OSes (such as Linux, FreeBSD, and NetBSD) are
    processing watch events using a single thread. If the events are received faster than the thread is able
    to handle, they will get queued. As the queue is unbounded, a guest may be able to trigger an OOM in the
    backend. All systems with a FreeBSD, Linux, or NetBSD (any version) dom0 are vulnerable. (CVE-2020-29568)

  - An issue was discovered in the Linux kernel through 5.10.1, as used with Xen through 4.14.x. The Linux
    kernel PV block backend expects the kernel thread handler to reset ring->xenblkd to NULL when stopped.
    However, the handler may not have time to run if the frontend quickly toggles between the states connect
    and disconnect. As a consequence, the block backend may re-use a pointer after it was freed. A misbehaving
    guest can trigger a dom0 crash by continuously connecting / disconnecting a block frontend. Privilege
    escalation and information leaks cannot be ruled out. This only affects systems with a Linux blkback.
    (CVE-2020-29569)

  - A locking inconsistency issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_io.c and drivers/tty/tty_jobctrl.c may allow a read-after-free attack against TIOCGSID,
    aka CID-c8bcd9c5be24. (CVE-2020-29660)

  - A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.
    (CVE-2020-29661)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1588.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19813");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-19816");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-27815");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-29568");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-29569");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-29660");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-29661");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update kernel' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19816");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-29569");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-aarch64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-livepatch-4.14.214-160.339");
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

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  cve_list = make_list("CVE-2019-19813", "CVE-2019-19816", "CVE-2020-27815", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661");
  if (hotfix_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "kpatch hotfix for ALAS-2021-1588");
  }
  else
  {
    __rpm_report = hotfix_reporting_text();
  }
}
pkgs = [
    {'reference':'kernel-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-common-aarch64-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-debuginfo-common-x86_64-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-devel-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-devel-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.214-160.339.amzn2', 'cpu':'i686', 'release':'AL2'},
    {'reference':'kernel-headers-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-livepatch-4.14.214-160.339-1.0-0.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-debuginfo-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-debuginfo-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'kernel-tools-devel-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'kernel-tools-devel-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perf-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perf-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perf-debuginfo-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perf-debuginfo-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python-perf-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python-perf-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python-perf-debuginfo-4.14.214-160.339.amzn2', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python-perf-debuginfo-4.14.214-160.339.amzn2', 'cpu':'x86_64', 'release':'AL2'}
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