#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101388);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2017-7895");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20170711)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - The NFSv2 and NFSv3 server implementations in the Linux
    kernel through 4.10.13 lacked certain checks for the end
    of a buffer. A remote attacker could trigger a
    pointer-arithmetic error or possibly cause other
    unspecified impacts using crafted requests related to
    fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c. (CVE-2017-7895,
    Important)

Bug Fix(es) :

  - If several file operations were started after a mounted
    NFS share had got idle and its Transmission Control
    Protocol (TCP) connection had therefore been terminated,
    these operations could cause multiple TCP SYN packets
    coming from the NFS client instead of one. With this
    update, the reconnection logic has been fixed, and only
    one TCP SYN packet is now sent in the described
    situation.

  - When the ixgbe driver was loaded for a
    backplane-connected network card, a kernel panic could
    occur, because the ops.setup_fc function pointer was
    used before the initialization. With this update,
    ops.setup_fc is initialized earlier. As a result, ixgbe
    no longer panics on load.

  - When setting an Access Control List (ACL) with 190 and
    more Access Control Entries (ACEs) on a NFSv4 directory,
    a kernel crash could previously occur. This update fixes
    the nfs4_getfacl() function, and the kernel no longer
    crashes under the described circumstances.

  - When upgrading to kernel with the fix for stack guard
    flaw, a crash could occur in Java Virtual Machine (JVM)
    environments, which attempted to implement their own
    stack guard page. With this update, the underlying
    source code has been fixed to consider the PROT_NONE
    mapping as a part of the stack, and the crash in JVM no
    longer occurs under the described circumstances.

  - When a program receives IPv6 packets using the raw
    socket, the ioctl(FIONREAD) and ioctl(SIOCINQ) functions
    can incorrectly return zero waiting bytes. This update
    fixes the ip6_input_finish() function to check the raw
    payload size properly. As a result, the ioctl() function
    now returns bytes waiting in the raw socket correctly.

  - Previously, listing a directory on a non-standard XFS
    filesystem (with non-default multi-fsb directory blocks)
    could lead to a soft lock up due to array index overrun
    in the xfs_dir2_leaf_readbuf() function. This update
    fixes xfs_dir2_leaf_readbuf(), and the soft lock up no
    longer occurs under the described circumstances.

  - Previously, aborts from the array after the Storage Area
    Network (SAN) fabric back-pressure led to premature
    reuse of still valid sequence with the same OX_ID.
    Consequently, an error message and data corruption could
    occur. This update fixes the libfc driver to isolate the
    timed out OX_IDs, thus fixing this bug.

  - Previously, a kernel panic occurred when the mcelog
    daemon executed a huge page memory offline. This update
    fixes the HugeTLB feature of the Linux kernel to check
    for the Page Table Entry (PTE) NULL pointer in the
    page_check_address() function. As a result, the kernel
    panic no longer occurs under the described
    circumstances."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1707&L=scientific-linux-errata&F=&S=&P=6470
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?318d4a01"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-696.6.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-696.6.3.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
}
