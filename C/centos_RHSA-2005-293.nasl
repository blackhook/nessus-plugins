#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:293 and 
# CentOS Errata and Security Advisory 2005:293 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21923);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2004-0075", "CVE-2004-0177", "CVE-2004-0814", "CVE-2004-1058", "CVE-2004-1073", "CVE-2005-0135", "CVE-2005-0137", "CVE-2005-0204", "CVE-2005-0384", "CVE-2005-0403", "CVE-2005-0449", "CVE-2005-0736", "CVE-2005-0749", "CVE-2005-0750");
  script_xref(name:"RHSA", value:"2005:293");

  script_name(english:"CentOS 3 : kernel (CESA-2005:293)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues in the Red
Hat Enterprise Linux 3 kernel are now available.

This security advisory has been rated as having important security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

The following security issues were fixed :

The Vicam USB driver did not use the copy_from_user function to access
userspace, crossing security boundaries. (CVE-2004-0075)

The ext3 and jfs code did not properly initialize journal descriptor
blocks. A privileged local user could read portions of kernel memory.
(CVE-2004-0177)

The terminal layer did not properly lock line discipline changes or
pending IO. An unprivileged local user could read portions of kernel
memory, or cause a denial of service (system crash). (CVE-2004-0814)

A race condition was discovered. Local users could use this flaw to
read the environment variables of another process that is still
spawning via /proc/.../cmdline. (CVE-2004-1058)

A flaw in the execve() syscall handling was discovered, allowing a
local user to read setuid ELF binaries that should otherwise be
protected by standard permissions. (CVE-2004-1073). Red Hat originally
reported this as being fixed by RHSA-2004:549, but the associated fix
was missing from that update.

Keith Owens reported a flaw in the Itanium unw_unwind_to_user()
function. A local user could use this flaw to cause a denial of
service (system crash) on the Itanium architecture. (CVE-2005-0135)

A missing Itanium syscall table entry could allow an unprivileged
local user to cause a denial of service (system crash) on the Itanium
architecture. (CVE-2005-0137)

A flaw affecting the OUTS instruction on the AMD64 and Intel EM64T
architectures was discovered. A local user could use this flaw to
access privileged IO ports. (CVE-2005-0204)

A flaw was discovered in the Linux PPP driver. On systems allowing
remote users to connect to a server using ppp, a remote client could
cause a denial of service (system crash). (CVE-2005-0384)

A flaw in the Red Hat backport of NPTL to Red Hat Enterprise Linux 3
was discovered that left a pointer to a freed tty structure. A local
user could potentially use this flaw to cause a denial of service
(system crash) or possibly gain read or write access to ttys that
should normally be prevented. (CVE-2005-0403)

A flaw in fragment queuing was discovered affecting the netfilter
subsystem. On systems configured to filter or process network packets
(for example those configured to do firewalling), a remote attacker
could send a carefully crafted set of fragmented packets to a machine
and cause a denial of service (system crash). In order to sucessfully
exploit this flaw, the attacker would need to know (or guess) some
aspects of the firewall ruleset in place on the target system to be
able to craft the right fragmented packets. (CVE-2005-0449)

Missing validation of an epoll_wait() system call parameter could
allow a local user to cause a denial of service (system crash) on the
IBM S/390 and zSeries architectures. (CVE-2005-0736)

A flaw when freeing a pointer in load_elf_library was discovered. A
local user could potentially use this flaw to cause a denial of
service (system crash). (CVE-2005-0749)

A flaw was discovered in the bluetooth driver system. On system where
the bluetooth modules are loaded, a local user could use this flaw to
gain elevated (root) privileges. (CVE-2005-0750)

In addition to the security issues listed above, there was an
important fix made to the handling of the msync() system call for a
particular case in which the call could return without queuing
modified mmap()'ed data for file system update. (BZ 147969)

Note: The kernel-unsupported package contains various drivers and
modules that are unsupported and therefore might contain security
problems that have not been addressed.

Red Hat Enterprise Linux 3 users are advised to upgrade their kernels
to the packages associated with their machine
architectures/configurations

Please note that the fix for CVE-2005-0449 required changing the
external symbol linkages (kernel module ABI) for the ip_defrag() and
ip_ct_gather_frags() functions. Any third-party module using either of
these would also need to be fixed."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011589.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01b5e952"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011590.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ecd71e1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011592.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a444c1e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"kernel-2.4.21-27.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-27.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-doc-2.4.21-27.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-27.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-27.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-27.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-27.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-27.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-27.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-source-2.4.21-27.0.4.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-unsupported-2.4.21-27.0.4.EL")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-doc / kernel-hugemem / etc");
}
