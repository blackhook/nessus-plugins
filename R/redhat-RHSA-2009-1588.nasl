#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1588. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63902);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-3547");
  script_bugtraq_id(36901);
  script_xref(name:"RHSA", value:"2009:1588");

  script_name(english:"RHEL 4 : kernel (RHSA-2009:1588)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix security issues are now available for
Red Hat Enterprise Linux 4.7 Extended Update Support.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* a NULL pointer dereference flaw was found in each of the following
functions in the Linux kernel: pipe_read_open(), pipe_write_open(),
and pipe_rdwr_open(). When the mutex lock is not held, the i_pipe
pointer could be released by other processes before it is used to
update the pipe's reader and writer counters. This could lead to a
local denial of service or privilege escalation. (CVE-2009-3547,
Important)

Users should upgrade to these updated packages, which contain a
backported patch to correct these issues. The system must be rebooted
for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kbase.redhat.com/faq/docs/DOC-20481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1588.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-devel-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", reference:"kernel-doc-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-hugemem-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-hugemem-devel-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-smp-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-smp-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-smp-devel-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-xenU-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-xenU-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"i686", reference:"kernel-xenU-devel-2.6.9-78.0.28.EL")) flag++;
if (rpm_check(release:"RHEL4", sp:"7", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-78.0.28.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
