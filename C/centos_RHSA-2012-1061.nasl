#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1061 and 
# CentOS Errata and Security Advisory 2012:1061 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59939);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-3375");
  script_bugtraq_id(54283);
  script_xref(name:"RHSA", value:"2012:1061");

  script_name(english:"CentOS 5 : kernel (CESA-2012:1061)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and multiple bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fix :

* The fix for CVE-2011-1083 (RHSA-2012:0150) introduced a flaw in the
way the Linux kernel's Event Poll (epoll) subsystem handled resource
clean up when an ELOOP error code was returned. A local, unprivileged
user could use this flaw to cause a denial of service. (CVE-2012-3375,
Moderate)

Bug fixes :

* The qla2xxx driver handled interrupts for QLogic Fibre Channel
adapters incorrectly due to a bug in a test condition for MSI-X
support. This update corrects the bug and qla2xxx now handles
interrupts as expected. (BZ#816373)

* A process scheduler did not handle RPC priority wait queues
correctly. Consequently, the process scheduler failed to wake up all
scheduled tasks as expected after RPC timeout, which caused the system
to become unresponsive and could significantly decrease system
performance. This update modifies the process scheduler to handle RPC
priority wait queues as expected. All scheduled tasks are now properly
woken up after RPC timeout and the system behaves as expected.
(BZ#817571)

* The kernel version 2.6.18-308.4.1.el5 contained several bugs which
led to an overrun of the NFS server page array. Consequently, any
attempt to connect an NFS client running on Red Hat Enterprise Linux
5.8 to the NFS server running on the system with this kernel caused
the NFS server to terminate unexpectedly and the kernel to panic. This
update corrects the bugs causing NFS page array overruns and the
kernel no longer crashes in this scenario. (BZ#820358)

* An insufficiently designed calculation in the CPU accelerator in the
previous kernel caused an arithmetic overflow in the sched_clock()
function when system uptime exceeded 208.5 days. This overflow led to
a kernel panic on the systems using the Time Stamp Counter (TSC) or
Virtual Machine Interface (VMI) clock source. This update corrects the
calculation so that this arithmetic overflow and kernel panic can no
longer occur under these circumstances.

Note: This advisory does not include a fix for this bug for the 32-bit
architecture. (BZ#824654)

* Under memory pressure, memory pages that are still a part of a
checkpointing transaction can be invalidated. However, when the pages
were invalidated, the journal head was re-filed onto the transactions'
'forget' list, which caused the current running transaction's block to
be modified. As a result, block accounting was not properly performed
on that modified block because it appeared to have already been
modified due to the journal head being re-filed. This could trigger an
assertion failure in the 'journal_commit_transaction()' function on
the system. The 'b_modified' flag is now cleared before the journal
head is filed onto any transaction; assertion failures no longer
occur. (BZ#827205)

* When running more than 30 instances of the cclengine utility
concurrently on IBM System z with IBM Communications Controller for
Linux, the system could become unresponsive. This was caused by a
missing wake_up() function call in the qeth_release_buffer() function
in the QETH network device driver. This update adds the missing
wake_up() function call and the system now responds as expected in
this scenario. (BZ#829059)

* Recent changes removing support for the Flow Director from the ixgbe
driver introduced bugs that caused the RSS (Receive Side Scaling)
functionality to stop working correctly on Intel 82599EB 10 Gigabit
Ethernet network devices. This update corrects the return code in the
ixgbe_cache_ring_fdir function and setting of the registers that
control the RSS redirection table. Also, obsolete code related to Flow
Director support has been removed. The RSS functionality now works as
expected on these devices. (BZ#832169)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-July/018707.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8da56c82"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3375");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-308.11.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-308.11.1.el5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-devel / kernel-debug / etc");
}
