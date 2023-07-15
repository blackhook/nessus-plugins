#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0783 and 
# CentOS Errata and Security Advisory 2015:0783 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82621);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-8159", "CVE-2014-8867");
  script_bugtraq_id(71331, 73060);
  script_xref(name:"RHSA", value:"2015:0783");

  script_name(english:"CentOS 5 : kernel (CESA-2015:0783)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and two bugs are
now available for Red Hat Enterprise Linux 5.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* It was found that the Linux kernel's Infiniband subsystem did not
properly sanitize input parameters while registering memory regions
from user space via the (u)verbs API. A local user with access to a
/dev/infiniband/uverbsX device could use this flaw to crash the system
or, potentially, escalate their privileges on the system.
(CVE-2014-8159, Important)

* An insufficient bound checking flaw was found in the Xen
hypervisor's implementation of acceleration support for the 'REP MOVS'
instructions. A privileged HVM guest user could potentially use this
flaw to crash the host. (CVE-2014-8867, Important)

Red Hat would like to thank Mellanox for reporting CVE-2014-8159, and
the Xen project for reporting CVE-2014-8867.

This update also fixes the following bugs :

* Under memory pressure, cached data was previously flushed to the
backing server using the PID of the thread responsible for flushing
the data in the Server Message Block (SMB) headers instead of the PID
of the thread which actually wrote the data. As a consequence, when a
file was locked by the writing thread prior to writing, the server
considered writes by the thread flushing the pagecache as being a
separate process from writing to a locked file, and thus rejected the
writes. In addition, the data to be written was discarded. This update
ensures that the correct PID is sent to the server, and data
corruption is avoided when data is being written from a client under
memory pressure. (BZ#1169304)

* This update adds support for new cryptographic hardware in
toleration mode for IBM System z. (BZ#1182522)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2015-April/021056.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8639f5d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8159");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/08");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"kernel-2.6.18-404.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-2.6.18-404.el5")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-404.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-2.6.18-404.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-debug-devel-2.6.18-404.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-devel-2.6.18-404.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-doc-2.6.18-404.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-headers-2.6.18-404.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-2.6.18-404.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kernel-xen-devel-2.6.18-404.el5")) flag++;


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
