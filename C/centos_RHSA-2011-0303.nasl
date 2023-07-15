#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0303 and 
# CentOS Errata and Security Advisory 2011:0303 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53422);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-4249", "CVE-2010-4251", "CVE-2010-4655", "CVE-2010-4805");
  script_bugtraq_id(45037, 45972);
  script_xref(name:"RHSA", value:"2011:0303");

  script_name(english:"CentOS 5 : kernel (CESA-2011:0303)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix three security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A flaw was found in the Linux kernel's garbage collector for AF_UNIX
sockets. A local, unprivileged user could use this flaw to trigger a
denial of service (out-of-memory condition). (CVE-2010-4249, Moderate)

* A flaw was found in the Linux kernel's networking subsystem. If the
number of packets received exceeded the receiver's buffer limit, they
were queued in a backlog, consuming memory, instead of being
discarded. A remote attacker could abuse this flaw to cause a denial
of service (out-of-memory condition). (CVE-2010-4251, Moderate)

* A missing initialization flaw was found in the ethtool_get_regs()
function in the Linux kernel's ethtool IOCTL handler. A local user who
has the CAP_NET_ADMIN capability could use this flaw to cause an
information leak. (CVE-2010-4655, Low)

Red Hat would like to thank Vegard Nossum for reporting CVE-2010-4249,
and Kees Cook for reporting CVE-2010-4655.

This update also fixes several bugs. Documentation for these bug fixes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs noted in
the Technical Notes. The system must be rebooted for this update to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017348.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45a1f5af"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-April/017349.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68423154"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-238.5.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-238.5.1.el5")) flag++;


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
