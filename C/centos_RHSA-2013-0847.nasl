#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0847 and 
# CentOS Errata and Security Advisory 2013:0847 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66528);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-0153");
  script_bugtraq_id(57745);
  script_xref(name:"RHSA", value:"2013:0847");

  script_name(english:"CentOS 5 : kernel (CESA-2013:0847)");
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

This update fixes the following security issue :

* A flaw was found in the way the Xen hypervisor AMD IOMMU driver
handled interrupt remapping entries. By default, a single interrupt
remapping table is used, and old interrupt remapping entries are not
cleared, potentially allowing a privileged guest user in a guest that
has a passed-through, bus-mastering capable PCI device to inject
interrupt entries into others guests, including the privileged
management domain (Dom0), leading to a denial of service.
(CVE-2013-0153, Moderate)

Red Hat would like to thank the Xen project for reporting the
CVE-2013-0153 issue.

This update also fixes the following bugs :

* When a process is opening a file over NFSv4, sometimes an OPEN call
can succeed while the following GETATTR operation fails with an
NFS4ERR_DELAY error. The NFSv4 code did not handle such a situation
correctly and allowed an NFSv4 client to attempt to use the buffer
that should contain the GETATTR information. However, the buffer did
not contain the valid GETATTR information, which caused the client to
return a '-ENOTDIR' error. Consequently, the process failed to open
the requested file. This update backports a patch that adds a test
condition verifying validity of the GETATTR information. If the
GETATTR information is invalid, it is obtained later and the process
opens the requested file as expected. (BZ#947736)

* Previously, the xdr routines in NFS version 2 and 3 conditionally
updated the res->count variable. Read retry attempts after a short NFS
read() call could fail to update the res->count variable, resulting in
truncated read data being returned. With this update, the res->count
variable is updated unconditionally so this bug can no longer occur.
(BZ#952098)

* When handling requests from Intelligent Platform Management
Interface (IPMI) clients, the IPMI driver previously used two
different locks for an IPMI request. If two IPMI clients sent their
requests at the same time, each request could receive one of the locks
and then wait for the second lock to become available. This resulted
in a deadlock situation and the system became unresponsive. The
problem could occur more likely in environments with many IPMI
clients. This update modifies the IPMI driver to handle the received
messages using tasklets so the driver now uses a safe locking
technique when handling IPMI requests and the mentioned deadlock can
no longer occur. (BZ#953435)

* Incorrect locking around the cl_state_owners list could cause the
NFSv4 state reclaimer thread to enter an infinite loop while holding
the Big Kernel Lock (BLK). As a consequence, the NFSv4 client became
unresponsive. With this update, safe list iteration is used, which
prevents the NFSv4 client from hanging in this scenario. (BZ#954296)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-May/019735.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36f81774"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0153");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-348.6.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-348.6.1.el5")) flag++;


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
