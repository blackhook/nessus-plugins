#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2152 and 
# CentOS Errata and Security Advisory 2015:2152 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87135);
  script_version("2.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-5313", "CVE-2013-7421", "CVE-2014-3647", "CVE-2014-7842", "CVE-2014-8171", "CVE-2014-9419", "CVE-2014-9644", "CVE-2015-0239", "CVE-2015-2925", "CVE-2015-3288", "CVE-2015-3339", "CVE-2015-4170", "CVE-2015-5283", "CVE-2015-6526", "CVE-2015-7553", "CVE-2015-7613", "CVE-2015-7837", "CVE-2015-8215", "CVE-2016-0774");
  script_xref(name:"RHSA", value:"2015:2152");

  script_name(english:"CentOS 7 : kernel (CESA-2015:2152)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix multiple security issues, address
several hundred bugs, and add numerous enhancements are now available
as part of the ongoing support and maintenance of Red Hat Enterprise
Linux version 7. This is the second regular update.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* A flaw was found in the way the Linux kernel's file system
implementation handled rename operations in which the source was
inside and the destination was outside of a bind mount. A privileged
user inside a container could use this flaw to escape the bind mount
and, potentially, escalate their privileges on the system.
(CVE-2015-2925, Important)

* A race condition flaw was found in the way the Linux kernel's IPC
subsystem initialized certain fields in an IPC object structure that
were later used for permission checking before inserting the object
into a globally visible list. A local, unprivileged user could
potentially use this flaw to elevate their privileges on the system.
(CVE-2015-7613, Important)

* It was found that reporting emulation failures to user space could
lead to either a local (CVE-2014-7842) or a L2->L1 (CVE-2010-5313)
denial of service. In the case of a local denial of service, an
attacker must have access to the MMIO area or be able to access an I/O
port. (CVE-2010-5313, CVE-2014-7842, Moderate)

* A flaw was found in the way the Linux kernel's KVM subsystem handled
non-canonical addresses when emulating instructions that change the
RIP (for example, branches or calls). A guest user with access to an
I/O or MMIO region could use this flaw to crash the guest.
(CVE-2014-3647, Moderate)

* It was found that the Linux kernel memory resource controller's
(memcg) handling of OOM (out of memory) conditions could lead to
deadlocks. An attacker could use this flaw to lock up the system.
(CVE-2014-8171, Moderate)

* A race condition flaw was found between the chown and execve system
calls. A local, unprivileged user could potentially use this flaw to
escalate their privileges on the system. (CVE-2015-3339, Moderate)

* A flaw was discovered in the way the Linux kernel's TTY subsystem
handled the tty shutdown phase. A local, unprivileged user could use
this flaw to cause a denial of service on the system. (CVE-2015-4170,
Moderate)

* A NULL pointer dereference flaw was found in the SCTP
implementation. A local user could use this flaw to cause a denial of
service on the system by triggering a kernel panic when creating
multiple sockets in parallel while the system did not have the SCTP
module loaded. (CVE-2015-5283, Moderate)

* A flaw was found in the way the Linux kernel's perf subsystem
retrieved userlevel stack traces on PowerPC systems. A local,
unprivileged user could use this flaw to cause a denial of service on
the system. (CVE-2015-6526, Moderate)

* A flaw was found in the way the Linux kernel's Crypto subsystem
handled automatic loading of kernel modules. A local user could use
this flaw to load any installed kernel module, and thus increase the
attack surface of the running kernel. (CVE-2013-7421, CVE-2014-9644,
Low)

* An information leak flaw was found in the way the Linux kernel
changed certain segment registers and thread-local storage (TLS)
during a context switch. A local, unprivileged user could use this
flaw to leak the user space TLS base address of an arbitrary process.
(CVE-2014-9419, Low)

* It was found that the Linux kernel KVM subsystem's sysenter
instruction emulation was not sufficient. An unprivileged guest user
could use this flaw to escalate their privileges by tricking the
hypervisor to emulate a SYSENTER instruction in 16-bit mode, if the
guest OS did not initialize the SYSENTER model-specific registers
(MSRs). Note: Certified guest operating systems for Red Hat Enterprise
Linux with KVM do initialize the SYSENTER MSRs and are thus not
vulnerable to this issue when running on a KVM hypervisor.
(CVE-2015-0239, Low)

* A flaw was found in the way the Linux kernel handled the securelevel
functionality after performing a kexec operation. A local attacker
could use this flaw to bypass the security mechanism of the
securelevel/secureboot combination. (CVE-2015-7837, Low)"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002347.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b522bf0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3288");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-327.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-327.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-327.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-327.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-327.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / kernel-debug-devel / etc");
}
