#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0147 and 
# Oracle Linux Security Advisory ELSA-2010-0147 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68014);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/24");

  script_cve_id("CVE-2009-4308", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0008", "CVE-2010-0415", "CVE-2010-0437");
  script_bugtraq_id(37724, 37762, 38144, 38185);
  script_xref(name:"RHSA", value:"2010:0147");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2010-0147)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0147 :

Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* a NULL pointer dereference flaw was found in the sctp_rcv_ootb()
function in the Linux kernel Stream Control Transmission Protocol
(SCTP) implementation. A remote attacker could send a specially
crafted SCTP packet to a target system, resulting in a denial of
service. (CVE-2010-0008, Important)

* a missing boundary check was found in the do_move_pages() function
in the memory migration functionality in the Linux kernel. A local
user could use this flaw to cause a local denial of service or an
information leak. (CVE-2010-0415, Important)

* a NULL pointer dereference flaw was found in the
ip6_dst_lookup_tail() function in the Linux kernel. An attacker on the
local network could trigger this flaw by sending IPv6 traffic to a
target system, leading to a system crash (kernel OOPS) if
dst->neighbour is NULL on the target system when receiving an IPv6
packet. (CVE-2010-0437, Important)

* a NULL pointer dereference flaw was found in the ext4 file system
code in the Linux kernel. A local attacker could use this flaw to
trigger a local denial of service by mounting a specially crafted,
journal-less ext4 file system, if that file system forced an EROFS
error. (CVE-2009-4308, Moderate)

* an information leak was found in the print_fatal_signal()
implementation in the Linux kernel. When
'/proc/sys/kernel/print-fatal-signals' is set to 1 (the default value
is 0), memory that is reachable by the kernel could be leaked to
user-space. This issue could also result in a system crash. Note that
this flaw only affected the i386 architecture. (CVE-2010-0003,
Moderate)

* missing capability checks were found in the ebtables implementation,
used for creating an Ethernet bridge firewall. This could allow a
local, unprivileged user to bypass intended capability restrictions
and modify ebtables rules. (CVE-2010-0007, Low)

Bug fixes :

* a bug prevented Wake on LAN (WoL) being enabled on certain Intel
hardware. (BZ#543449)

* a race issue in the Journaling Block Device. (BZ#553132)

* programs compiled on x86, and that also call
sched_rr_get_interval(), were silently corrupted when run on 64-bit
systems. (BZ#557684)

* the RHSA-2010:0019 update introduced a regression, preventing WoL
from working for network devices using the e1000e driver. (BZ#559335)

* adding a bonding interface in mode balance-alb to a bridge was not
functional. (BZ#560588)

* some KVM (Kernel-based Virtual Machine) guests experienced slow
performance (and possibly a crash) after suspend/resume. (BZ#560640)

* on some systems, VF cannot be enabled in dom0. (BZ#560665)

* on systems with certain network cards, a system crash occurred after
enabling GRO. (BZ#561417)

* for x86 KVM guests with pvclock enabled, the boot clocks were
registered twice, possibly causing KVM to write data to a random
memory area during the guest's life. (BZ#561454)

* serious performance degradation for 32-bit applications, that map
(mmap) thousands of small files, when run on a 64-bit system.
(BZ#562746)

* improved kexec/kdump handling. Previously, on some systems under
heavy load, kexec/kdump was not functional. (BZ#562772)

* dom0 was unable to boot when using the Xen hypervisor on a system
with a large number of logical CPUs. (BZ#562777)

* a fix for a bug that could potentially cause file system corruption.
(BZ#564281)

* a bug caused infrequent cluster issues for users of GFS2.
(BZ#564288)

* gfs2_delete_inode failed on read-only file systems. (BZ#564290)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-March/001393.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("ksplice.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  cve_list = make_list("CVE-2009-4308", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0008", "CVE-2010-0415", "CVE-2010-0437");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2010-0147");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "2.6";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-2.6.18-164.15.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-2.6.18-164.15.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-devel-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-164.15.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-2.6.18-164.15.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-devel-2.6.18-164.15.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-devel-2.6.18-164.15.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.18") && rpm_check(release:"EL5", reference:"kernel-doc-2.6.18-164.15.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.18") && rpm_check(release:"EL5", reference:"kernel-headers-2.6.18-164.15.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-2.6.18-164.15.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-devel-2.6.18-164.15.1.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
