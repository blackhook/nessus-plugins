#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1065 and 
# CentOS Errata and Security Advisory 2011:1065 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56265);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-1780", "CVE-2011-2525", "CVE-2011-2689");
  script_bugtraq_id(48610, 48641, 48677);
  script_xref(name:"RHSA", value:"2011:1065");

  script_name(english:"CentOS 5 : kernel (CESA-2011:1065)");
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
Linux version 5. This is the seventh regular update.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw was found in the way the Xen hypervisor implementation
handled instruction emulation during virtual machine exits. A
malicious user-space process running in an SMP guest could trick the
emulator into reading a different instruction than the one that caused
the virtual machine to exit. An unprivileged guest user could trigger
this flaw to crash the host. This only affects systems with both an
AMD x86 processor and the AMD Virtualization (AMD-V) extensions
enabled. (CVE-2011-1780, Important)

* A flaw allowed the tc_fill_qdisc() function in the Linux kernel's
packet scheduler API implementation to be called on built-in qdisc
structures. A local, unprivileged user could use this flaw to trigger
a NULL pointer dereference, resulting in a denial of service.
(CVE-2011-2525, Moderate)

* A flaw was found in the way space was allocated in the Linux
kernel's Global File System 2 (GFS2) implementation. If the file
system was almost full, and a local, unprivileged user made an
fallocate() request, it could result in a denial of service. Note:
Setting quotas to prevent users from using all available disk space
would prevent exploitation of this flaw. (CVE-2011-2689, Moderate)

These updated kernel packages include a number of bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Refer to the Red Hat Enterprise Linux 5.7 Technical Notes
for information about the most significant bug fixes and enhancements
included in this update :

https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/
5.7_Technical_Notes/kernel.html#RHSA-2011-1065

All Red Hat Enterprise Linux 5 users are advised to install these
updated packages, which correct these issues. The system must be
rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45fb7621"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017865.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce55b577"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000066.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0ccef8a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000067.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?80df715a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-274.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-274.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-274.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-274.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-274.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-274.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-274.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-274.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-274.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-274.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-devel / kernel-debug / etc");
}
