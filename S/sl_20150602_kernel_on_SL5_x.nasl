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
  script_id(83969);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-1805");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64 (20150602)");
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
"  - It was found that the Linux kernel's implementation of
    vectored pipe read and write functionality did not take
    into account the I/O vectors that were already processed
    when retrying after a failed atomic access operation,
    potentially resulting in memory corruption due to an I/O
    vector array overrun. A local, unprivileged user could
    use this flaw to crash the system or, potentially,
    escalate their privileges on the system. (CVE-2015-1805,
    Important)

This update fixes the following bugs :

  - Due to a bug in the lpfc_device_reset_handler()
    function, a scsi command timeout could lead to a system
    crash. With this update, lpfc_device_reset_handler
    recovers storage without crashing.

  - Due to the code decrementing the reclaim_in_progress
    counter without having incremented it first, severe
    spinlock contention occurred in the shrink_zone()
    function even though the vm.max_reclaims_in_progress
    feature was set to 1. This update provides a patch
    fixing the underlying source code, and spinlock
    contention no longer occurs in this scenario.

  - A TCP socket using SACK that had a retransmission but
    recovered from it, failed to reset the retransmission
    timestamp. As a consequence, on certain connections, if
    a packet had to be re-transmitted, the retrans_stamp
    variable was only cleared when the next acked packet was
    received. This could lead to an early abortion of the
    TCP connection if this next packet also got lost. With
    this update, the socket clears retrans_stamp when the
    recovery is completed, thus fixing the bug.

  - Previously, the signal delivery paths did not clear the
    TS_USEDFPU flag, which could cause problems in the
    switch_to() function and lead to floating-point unit
    (FPU) corruption. With this update, TS_USEDFPU is
    cleared as expected, and FPU is no longer under threat
    of corruption.

  - A race condition in the exit_sem() function previously
    caused the semaphore undo list corruption. As a
    consequence, a kernel crash could occur. The corruption
    in the semaphore undo list has been fixed, and the
    kernel no longer crashes in this situation.

  - Previously, when running the 'virsh blockresize [Device]
    [Newsize]' command to resize the disk, the new size was
    not reflected in a Scientific Linux 5 Virtual Machine
    (VM). With this update, the new size is now reflected
    online immediately in a Scientific Linux 5 VM so it is
    no longer necessary to reboot the VM to see the new disk
    size.

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1506&L=scientific-linux-errata&F=&S=&P=2521
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?445adbb2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-406.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-406.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-debuginfo / kernel-PAE-devel / etc");
}
