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
  script_id(80099);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-6657", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-6410", "CVE-2014-9322");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20141216)");
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
"  - A flaw was found in the way the Linux kernel's SCTP
    implementation handled malformed or duplicate Address
    Configuration Change Chunks (ASCONF). A remote attacker
    could use either of these flaws to crash the system.
    (CVE-2014-3673, CVE-2014-3687, Important)

  - A flaw was found in the way the Linux kernel's SCTP
    implementation handled the association's output queue. A
    remote attacker could send specially crafted packets
    that would cause the system to use an excessive amount
    of memory, leading to a denial of service.
    (CVE-2014-3688, Important)

  - A stack overflow flaw caused by infinite recursion was
    found in the way the Linux kernel's UDF file system
    implementation processed indirect ICBs. An attacker with
    physical access to the system could use a specially
    crafted UDF image to crash the system. (CVE-2014-6410,
    Low)

  - It was found that the Linux kernel's networking
    implementation did not correctly handle the setting of
    the keepalive socket option on raw sockets. A local user
    able to create a raw socket could use this flaw to crash
    the system. (CVE-2012-6657, Low)

  - It was found that the parse_rock_ridge_inode_internal()
    function of the Linux kernel's ISOFS implementation did
    not correctly check relocated directories when
    processing Rock Ridge child link (CL) tags. An attacker
    with physical access to the system could use a specially
    crafted ISO image to crash the system or, potentially,
    escalate their privileges on the system. (CVE-2014-5471,
    CVE-2014-5472, Low)

Bug fixes :

  - This update fixes a race condition issue between the
    sock_queue_err_skb function and sk_forward_alloc
    handling in the socket error queue (MSG_ERRQUEUE), which
    could occasionally cause the kernel, for example when
    using PTP, to incorrectly track allocated memory for the
    error queue, in which case a traceback would occur in
    the system log.

  - The zcrypt device driver did not detect certain crypto
    cards and the related domains for crypto adapters on
    System z and s390x architectures. Consequently, it was
    not possible to run the system on new crypto hardware.
    This update enables toleration mode for such devices so
    that the system can make use of newer crypto hardware.

  - After mounting and unmounting an XFS file system several
    times consecutively, the umount command occasionally
    became unresponsive. This was caused by the
    xlog_cil_force_lsn() function that was not waiting for
    completion as expected. With this update,
    xlog_cil_force_lsn() has been modified to correctly wait
    for completion, thus fixing this bug.

  - When using the ixgbe adapter with disabled LRO and the
    tx-usec or rs- usec variables set to 0, transmit
    interrupts could not be set lower than the default of 8
    buffered tx frames. Consequently, a delay of TCP
    transfer occurred. The restriction of a minimum of 8
    buffered frames has been removed, and the TCP delay no
    longer occurs.

  - The offb driver has been updated for the QEMU standard
    VGA adapter, fixing an incorrect displaying of colors
    issue.

  - Under certain circumstances, when a discovered MTU
    expired, the IPv6 connection became unavailable for a
    short period of time. This bug has been fixed, and the
    connection now works as expected.

  - A low throughput occurred when using the dm-thin driver
    to write to unprovisioned or shared chunks for a thin
    pool with the chunk size bigger than the max_sectors_kb
    variable.

  - Large write workloads on thin LVs could cause the iozone
    and smallfile utilities to terminate unexpectedly."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=2965
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?950ff48d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-504.3.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-504.3.3.el6")) flag++;


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
