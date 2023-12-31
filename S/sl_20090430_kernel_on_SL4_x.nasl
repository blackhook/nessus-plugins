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
  script_id(60577);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-4307", "CVE-2009-0028", "CVE-2009-0676", "CVE-2009-0834");

  script_name(english:"Scientific Linux Security Update : kernel on SL4.x i386/x86_64");
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
"Security fixes :

  - a logic error was found in the do_setlk() function of
    the Linux kernel Network File System (NFS)
    implementation. If a signal interrupted a lock request,
    the local POSIX lock was incorrectly created. This could
    cause a denial of service on the NFS server if a file
    descriptor was closed before its corresponding lock
    request returned. (CVE-2008-4307, Important)

  - a deficiency was found in the Linux kernel system call
    auditing implementation on 64-bit systems. This could
    allow a local, unprivileged user to circumvent a system
    call audit configuration, if that configuration filtered
    based on the 'syscall' number or arguments.
    (CVE-2009-0834, Important)

  - Chris Evans reported a deficiency in the Linux kernel
    signals implementation. The clone() system call permits
    the caller to indicate the signal it wants to receive
    when its child exits. When clone() is called with the
    CLONE_PARENT flag, it permits the caller to clone a new
    child that shares the same parent as itself, enabling
    the indicated signal to be sent to the caller's parent
    (instead of the caller), even if the caller's parent has
    different real and effective user IDs. This could lead
    to a denial of service of the parent. (CVE-2009-0028,
    Moderate)

  - the sock_getsockopt() function in the Linux kernel did
    not properly initialize a data structure that can be
    directly returned to user-space when the getsockopt()
    function is called with SO_BSDCOMPAT optname set. This
    flaw could possibly lead to memory disclosure.
    (CVE-2009-0676, Moderate)

Bug fixes :

  - a kernel crash may have occurred for Scientific Linux
    4.7 guests if their guest configuration file specified
    'vif = [ 'type=ioemu' ]'. This crash only occurred when
    starting guests via the 'xm create' command. (BZ#477146)

  - a bug in IO-APIC NMI watchdog may have prevented
    Scientific Linux 4.7 from being installed on HP ProLiant
    DL580 G5 systems. Hangs during installation and 'NMI
    received for unknown reason [xx]' errors may have
    occurred. (BZ#479184)

  - a kernel deadlock on some systems when using netdump
    through a network interface that uses the igb driver.
    (BZ#480579)

  - a possible kernel hang in sys_ptrace() on the
    Itanium&reg; architecture, possibly triggered by tracing
    a threaded process with strace. (BZ#484904)

  - the RHSA-2008:0665 errata only fixed the known problem
    with the LSI Logic LSI53C1030 Ultra320 SCSI controller,
    for tape devices. Read commands sent to tape devices may
    have received incorrect data. This issue may have led to
    data corruption. This update includes a fix for all
    types of devices. (BZ#487399)

  - a missing memory barrier caused a race condition in the
    AIO subsystem between the read_events() and
    aio_complete() functions. This may have caused a thread
    in read_events() to sleep indefinitely, possibly causing
    an application hang. (BZ#489935)

  - due to a lack of synchronization in the NFS client code,
    modifications to some pages (for files on an NFS mounted
    file system) made through a region of memory mapped by
    mmap() may be lost if the NFS client invalidates its
    page cache for particular files. (BZ#490119)

  - a NULL pointer dereference in the megaraid_mbox driver
    caused a system crash on some systems. (BZ#493420)

  - the ext3_symlink() function in the ext3 file system code
    used an illegal __GFP_FS allocation inside some
    transactions. This may have resulted in a kernel panic
    and 'Assertion failure' errors. (BZ#493422)

  - do_machine_check() cleared all Machine Check Exception
    (MCE) status registers, preventing the BIOS from using
    them to determine the cause of certain panics and
    errors. (BZ#494915)

  - a bug prevented NMI watchdog from initializing on HP
    ProLiant DL580 G5 systems. (BZ#497330)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=477146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=479184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=480579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=484904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=487399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=489935"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=490119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=493420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=493422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=494915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=497330"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0905&L=scientific-linux-errata&T=0&P=319
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?93c098ce"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_cwe_id(264, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"kernel-2.6.9-78.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-devel-2.6.9-78.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-doc-2.6.9-78.0.22.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-78.0.22.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-78.0.22.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.22.EL")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-2.6.9-78.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-smp-devel-2.6.9-78.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-2.6.9-78.0.22.EL")) flag++;
if (rpm_check(release:"SL4", reference:"kernel-xenU-devel-2.6.9-78.0.22.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
