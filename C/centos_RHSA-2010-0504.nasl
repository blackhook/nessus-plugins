#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0504 and 
# CentOS Errata and Security Advisory 2010:0504 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47702);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0291", "CVE-2010-0622", "CVE-2010-1087", "CVE-2010-1088", "CVE-2010-1173", "CVE-2010-1187", "CVE-2010-1436", "CVE-2010-1437", "CVE-2010-1641");
  script_bugtraq_id(37906, 38165, 39044, 39120, 39569, 39719, 39794, 40356);
  script_xref(name:"RHSA", value:"2010:0504");

  script_name(english:"CentOS 5 : kernel (CESA-2010:0504)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* multiple flaws were found in the mmap and mremap implementations. A
local user could use these flaws to cause a local denial of service or
escalate their privileges. (CVE-2010-0291, Important)

* a NULL pointer dereference flaw was found in the Fast Userspace
Mutexes (futexes) implementation. The unlock code path did not check
if the futex value associated with pi_state->owner had been modified.
A local user could use this flaw to modify the futex value, possibly
leading to a denial of service or privilege escalation when the
pi_state->owner pointer is dereferenced. (CVE-2010-0622, Important)

* a NULL pointer dereference flaw was found in the Linux kernel
Network File System (NFS) implementation. A local user on a system
that has an NFS-mounted file system could use this flaw to cause a
denial of service or escalate their privileges on that system.
(CVE-2010-1087, Important)

* a flaw was found in the sctp_process_unk_param() function in the
Linux kernel Stream Control Transmission Protocol (SCTP)
implementation. A remote attacker could send a specially crafted SCTP
packet to an SCTP listening port on a target system, causing a kernel
panic (denial of service). (CVE-2010-1173, Important)

* a flaw was found in the Linux kernel Transparent Inter-Process
Communication protocol (TIPC) implementation. If a client application,
on a local system where the tipc module is not yet in network mode,
attempted to send a message to a remote TIPC node, it would
dereference a NULL pointer on the local system, causing a kernel panic
(denial of service). (CVE-2010-1187, Important)

* a buffer overflow flaw was found in the Linux kernel Global File
System 2 (GFS2) implementation. In certain cases, a quota could be
written past the end of a memory page, causing memory corruption,
leaving the quota stored on disk in an invalid state. A user with
write access to a GFS2 file system could trigger this flaw to cause a
kernel crash (denial of service) or escalate their privileges on the
GFS2 server. This issue can only be triggered if the GFS2 file system
is mounted with the 'quota=on' or 'quota=account' mount option.
(CVE-2010-1436, Important)

* a race condition between finding a keyring by name and destroying a
freed keyring was found in the Linux kernel key management facility. A
local user could use this flaw to cause a kernel panic (denial of
service) or escalate their privileges. (CVE-2010-1437, Important)

* a flaw was found in the link_path_walk() function in the Linux
kernel. Using the file descriptor returned by the open() function with
the O_NOFOLLOW flag on a subordinate NFS-mounted file system, could
result in a NULL pointer dereference, causing a denial of service or
privilege escalation. (CVE-2010-1088, Moderate)

* a missing permission check was found in the gfs2_set_flags()
function in the Linux kernel GFS2 implementation. A local user could
use this flaw to change certain file attributes of files, on a GFS2
file system, that they do not own. (CVE-2010-1641, Low)

Red Hat would like to thank Jukka Taimisto and Olli Jarva of
Codenomicon Ltd, Nokia Siemens Networks, and Wind River on behalf of
their customer, for responsibly reporting CVE-2010-1173; Mario
Mikocevic for responsibly reporting CVE-2010-1436; and Dan Rosenberg
for responsibly reporting CVE-2010-1641.

This update also fixes several bugs. Documentation for these bug fixes
will be available shortly from
http://www.redhat.com/docs/en-US/errata/RHSA-2010-0504/Kernel_Security
_Update/ index.html

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016747.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f554f20"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016748.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e0e8298"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(264);

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-194.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-194.8.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-devel / kernel-debug / etc");
}
