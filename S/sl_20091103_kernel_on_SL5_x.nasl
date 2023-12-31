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
  script_id(65044);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-2695", "CVE-2009-2908", "CVE-2009-3228", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3613");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
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
"CVE-2009-2695 kernel: SELinux and mmap_min_addr

CVE-2009-3228 kernel: tc: uninitialised kernel memory leak

CVE-2009-3286 kernel: O_EXCL creates on NFSv4 are broken

CVE-2009-2908 kernel ecryptfs NULL pointer dereference

CVE-2009-3613 kernel: flood ping cause out-of-iommu error and panic
when mtu larger than 1500

CVE-2009-3547 kernel: fs: pipe.c NULL pointer dereference

Security fixes :

  - a system with SELinux enforced was more permissive in
    allowing local users in the unconfined_t domain to map
    low memory areas even if the mmap_min_addr restriction
    was enabled. This could aid in the local exploitation of
    NULL pointer dereference bugs. (CVE-2009-2695,
    Important)

  - a NULL pointer dereference flaw was found in the
    eCryptfs implementation in the Linux kernel. A local
    attacker could use this flaw to cause a local denial of
    service or escalate their privileges. (CVE-2009-2908,
    Important)

  - a flaw was found in the NFSv4 implementation. The kernel
    would do an unnecessary permission check after creating
    a file. This check would usually fail and leave the file
    with the permission bits set to random values. Note:
    This is a server-side only issue. (CVE-2009-3286,
    Important)

  - a NULL pointer dereference flaw was found in each of the
    following functions in the Linux kernel:
    pipe_read_open(), pipe_write_open(), and
    pipe_rdwr_open(). When the mutex lock is not held, the
    i_pipe pointer could be released by other processes
    before it is used to update the pipe's reader and writer
    counters. This could lead to a local denial of service
    or privilege escalation. (CVE-2009-3547, Important)

  - a flaw was found in the Realtek r8169 Ethernet driver in
    the Linux kernel. pci_unmap_single() presented a memory
    leak that could lead to IOMMU space exhaustion and a
    system crash. An attacker on the local network could
    abuse this flaw by using jumbo frames for large amounts
    of network traffic. (CVE-2009-3613, Important)

  - missing initialization flaws were found in the Linux
    kernel. Padding data in several core network structures
    was not initialized properly before being sent to
    user-space. These flaws could lead to information leaks.
    (CVE-2009-3228, Moderate)

Bug fixes :

  - with network bonding in the 'balance-tlb' or
    'balance-alb' mode, the primary setting for the primary
    slave device was lost when said device was brought down.
    Bringing the slave back up did not restore the primary
    setting. (BZ#517971)

  - some faulty serial device hardware caused systems
    running the kernel-xen kernel to take a very long time
    to boot. (BZ#524153)

  - a caching bug in nfs_readdir() may have caused NFS
    clients to see duplicate files or not see all files in a
    directory. (BZ#526960)

  - the RHSA-2009:1243 update removed the mpt_msi_enable
    option, preventing certain scripts from running. This
    update adds the option back. (BZ#526963)

  - an iptables rule with the recent module and a hit count
    value greater than the ip_pkt_list_tot parameter (the
    default is 20), did not have any effect over packets, as
    the hit count could not be reached. (BZ#527434)

  - a check has been added to the IPv4 code to make sure
    that rt is not NULL, to help prevent future bugs in
    functions that call ip_append_data() from being
    exploitable. (BZ#527436)

  - a kernel panic occurred in certain conditions after
    reconfiguring a tape drive's block size. (BZ#528133)

  - when using the Linux Virtual Server (LVS) in a master
    and backup configuration, and propagating active
    connections on the master to the backup, the connection
    timeout value on the backup was hard-coded to 180
    seconds, meaning connection information on the backup
    was soon lost. This could prevent the successful
    failover of connections. The timeout value can now be
    set via 'ipvsadm --set'. (BZ#528645)

  - a bug in nfs4_do_open_expired() could have caused the
    reclaimer thread on an NFSv4 client to enter an infinite
    loop. (BZ#529162)

  - MSI interrupts may not have been delivered for r8169
    based network cards that have MSI interrupts enabled.
    This bug only affected certain systems. (BZ#529366)

The system must be rebooted for this update to take effect.

Note1: Due to the fuse kernel module now being part of the kernel, we
are updating fuse on the older releases to match the fuse that was
released by The Upstream Vendor.

Note2: kernel-module-openafs for SL 50-53 is for openafs 1.4.7, for SL
54 it is for openafs 1.4.11

Note3: xfs is now part of the kernel in x86_64. Because of this there
is no kernel-module-xfs for x86_64.

Note4: ipw3945 support has been changed to iwlwifi3945 in SL 54, and
is in the kernel. Because of this there is no kernel-module-ipw3945
for SL54.

Note5: Support for the Atheros chipset in now in the kernel. We are
not sure if the infrastructure is in place for SL 50-53, so we are
still providing the madwifi kernel modules for SL 50-53."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=517971"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=524153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=526960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=526963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=527434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=527436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=528133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=528645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=529162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=529366"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0911&L=scientific-linux-errata&T=0&P=722
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdbde572"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 200, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-164.6.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-164.6.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-164.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-164.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-164.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-164.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-164.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-164.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-164.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-164.6.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
