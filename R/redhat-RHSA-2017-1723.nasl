#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1723. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101386);
  script_version("3.12");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-7895");
  script_xref(name:"RHSA", value:"2017:1723");

  script_name(english:"RHEL 6 : kernel (RHSA-2017:1723)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for kernel is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es) :

* The NFSv2 and NFSv3 server implementations in the Linux kernel
through 4.10.13 lacked certain checks for the end of a buffer. A
remote attacker could trigger a pointer-arithmetic error or possibly
cause other unspecified impacts using crafted requests related to
fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c. (CVE-2017-7895, Important)

Red Hat would like to thank Ari Kauppi for reporting this issue.

Bug Fix(es) :

* If several file operations were started after a mounted NFS share
had got idle and its Transmission Control Protocol (TCP) connection
had therefore been terminated, these operations could cause multiple
TCP SYN packets coming from the NFS client instead of one. With this
update, the reconnection logic has been fixed, and only one TCP SYN
packet is now sent in the described situation. (BZ#1450850)

* When the ixgbe driver was loaded for a backplane-connected network
card, a kernel panic could occur, because the ops.setup_fc function
pointer was used before the initialization. With this update,
ops.setup_fc is initialized earlier. As a result, ixgbe no longer
panics on load. (BZ# 1457347)

* When setting an Access Control List (ACL) with 190 and more Access
Control Entries (ACEs) on a NFSv4 directory, a kernel crash could
previously occur. This update fixes the nfs4_getfacl() function, and
the kernel no longer crashes under the described circumstances.
(BZ#1449096)

* When upgrading to kernel with the fix for stack guard flaw, a crash
could occur in Java Virtual Machine (JVM) environments, which
attempted to implement their own stack guard page. With this update,
the underlying source code has been fixed to consider the PROT_NONE
mapping as a part of the stack, and the crash in JVM no longer occurs
under the described circumstances. (BZ#1466667)

* When a program receives IPv6 packets using the raw socket, the ioctl
(FIONREAD) and ioctl(SIOCINQ) functions can incorrectly return zero
waiting bytes. This update fixes the ip6_input_finish() function to
check the raw payload size properly. As a result, the ioctl() function
now returns bytes waiting in the raw socket correctly. (BZ#1450870)

* Previously, listing a directory on a non-standard XFS filesystem
(with non-default multi-fsb directory blocks) could lead to a soft
lock up due to array index overrun in the xfs_dir2_leaf_readbuf()
function. This update fixes xfs_dir2_leaf_readbuf(), and the soft lock
up no longer occurs under the described circumstances. (BZ#1445179)

* Previously, aborts from the array after the Storage Area Network
(SAN) fabric back-pressure led to premature reuse of still valid
sequence with the same OX_ID. Consequently, an error message and data
corruption could occur. This update fixes the libfc driver to isolate
the timed out OX_IDs, thus fixing this bug. (BZ#1455550)

* Previously, a kernel panic occurred when the mcelog daemon executed
a huge page memory offline. This update fixes the HugeTLB feature of
the Linux kernel to check for the Page Table Entry (PTE) NULL pointer
in the page_check_address() function. As a result, the kernel panic no
longer occurs under the described circumstances. (BZ#1444351)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7895"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");
include("ksplice.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2017-7895");
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for RHSA-2017:1723");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1723";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-abi-whitelists-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debug-devel-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-devel-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-devel-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-devel-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-doc-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"kernel-firmware-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kernel-headers-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-headers-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kernel-headers-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"perf-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"perf-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-perf-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-perf-debuginfo-2.6.32-696.6.3.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-perf-debuginfo-2.6.32-696.6.3.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
  }
}
