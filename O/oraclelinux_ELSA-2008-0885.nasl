#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0885 and 
# Oracle Linux Security Advisory ELSA-2008-0885 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67747);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/24");

  script_cve_id("CVE-2007-6417", "CVE-2007-6716", "CVE-2008-2931", "CVE-2008-3272", "CVE-2008-3275");
  script_bugtraq_id(27694, 30647, 31515);
  script_xref(name:"RHSA", value:"2008:0885");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2008-0885)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0885 :

Updated kernel packages that fix various security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* a missing capability check was found in the Linux kernel
do_change_type routine. This could allow a local unprivileged user to
gain privileged access or cause a denial of service. (CVE-2008-2931,
Important)

* a flaw was found in the Linux kernel Direct-IO implementation. This
could allow a local unprivileged user to cause a denial of service.
(CVE-2007-6716, Important)

* Tobias Klein reported a missing check in the Linux kernel Open Sound
System (OSS) implementation. This deficiency could lead to a possible
information leak. (CVE-2008-3272, Moderate)

* a deficiency was found in the Linux kernel virtual filesystem (VFS)
implementation. This could allow a local unprivileged user to attempt
file creation within deleted directories, possibly causing a denial of
service. (CVE-2008-3275, Moderate)

* a flaw was found in the Linux kernel tmpfs implementation. This
could allow a local unprivileged user to read sensitive information
from the kernel. (CVE-2007-6417, Moderate)

Bug fixes :

* when copying a small IPoIB packet from the original skb it was
received in to a new, smaller skb, all fields in the new skb were not
initialized. This may have caused a kernel oops.

* previously, data may have been written beyond the end of an array,
causing memory corruption on certain systems, resulting in hypervisor
crashes during context switching.

* a kernel crash may have occurred on heavily-used Samba servers after
24 to 48 hours of use.

* under heavy memory pressure, pages may have been swapped out from
under the SGI Altix XPMEM driver, causing silent data corruption in
the kernel.

* the ixgbe driver is untested, but support was advertised for the
Intel 82598 network card. If this card was present when the ixgbe
driver was loaded, a NULL pointer dereference and a panic occurred.

* on certain systems, if multiple InfiniBand queue pairs
simultaneously fell into an error state, an overrun may have occurred,
stopping traffic.

* with bridging, when forward delay was set to zero, setting an
interface to the forwarding state was delayed by one or possibly two
timers, depending on whether STP was enabled. This may have caused
long delays in moving an interface to the forwarding state. This issue
caused packet loss when migrating virtual machines, preventing them
from being migrated without interrupting applications.

* on certain multinode systems, IPMI device nodes were created in
reverse order of where they physically resided.

* process hangs may have occurred while accessing application data
files via asynchronous direct I/O system calls.

* on systems with heavy lock traffic, a possible deadlock may have
caused anything requiring locks over NFS to stop, or be very slow.
Errors such as 'lockd: server [IP] not responding, timed out' were
logged on client systems.

* unexpected removals of USB devices may have caused a NULL pointer
dereference in kobject_get_path.

* on Itanium-based systems, repeatedly creating and destroying Windows
guests may have caused Dom0 to crash, due to the
'XENMEM_add_to_physmap' hypercall, used by para-virtualized drivers on
HVM, being SMP-unsafe.

* when using an MD software RAID, crashes may have occurred when
devices were removed or changed while being iterated through. Correct
locking is now used.

* break requests had no effect when using 'Serial Over Lan' with the
Intel 82571 network card. This issue may have caused log in problems.

* on Itanium-based systems, module_free() referred the first parameter
before checking it was valid. This may have caused a kernel panic when
exiting SystemTap.

Red Hat Enterprise Linux 5 users are advised to upgrade to these
updated packages, which contain backported patches to resolve these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-September/000742.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 200, 264, 399);

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/25");
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
  cve_list = make_list("CVE-2007-6417", "CVE-2007-6716", "CVE-2008-2931", "CVE-2008-3272", "CVE-2008-3275");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2008-0885");
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
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-2.6.18-92.1.13.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-2.6.18-92.1.13.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-devel-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-92.1.13.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-2.6.18-92.1.13.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-devel-2.6.18-92.1.13.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-devel-2.6.18-92.1.13.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.18") && rpm_check(release:"EL5", reference:"kernel-doc-2.6.18-92.1.13.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.18") && rpm_check(release:"EL5", reference:"kernel-headers-2.6.18-92.1.13.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-2.6.18-92.1.13.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-devel-2.6.18-92.1.13.0.1.el5")) flag++;


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
