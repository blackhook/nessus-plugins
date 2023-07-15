#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0690 and 
# CentOS Errata and Security Advisory 2012:0690 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59312);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-2136");
  script_xref(name:"RHSA", value:"2012:0690");

  script_name(english:"CentOS 5 : kernel (CESA-2012:0690)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and various bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issue :

* It was found that the data_len parameter of the
sock_alloc_send_pskb() function in the Linux kernel's networking
implementation was not validated before use. A local user with access
to a TUN/TAP virtual interface could use this flaw to crash the system
or, potentially, escalate their privileges. Note that unprivileged
users cannot access TUN/TAP devices until the root user grants them
access. (CVE-2012-2136, Important)

This update also fixes various bugs. Documentation for these changes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct this issue, and fix the bugs noted in
the Technical Notes. The system must be rebooted for this update to
take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-May/018661.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b16a0972"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2136");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/31");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-308.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-308.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-308.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-308.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-308.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-308.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-308.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-308.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-308.8.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-308.8.1.el5")) flag++;


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
