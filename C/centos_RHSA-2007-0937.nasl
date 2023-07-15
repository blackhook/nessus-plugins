#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0937 and 
# CentOS Errata and Security Advisory 2007:0937 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26206);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-4573");
  script_bugtraq_id(25774);
  script_xref(name:"RHSA", value:"2007:0937");

  script_name(english:"CentOS 4 : kernel (CESA-2007:0937)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix a security issue in the Red Hat
Enterprise Linux 4 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

A flaw was found in the IA32 system call emulation provided on AMD64
and Intel 64 platforms. An improperly validated 64-bit value could be
stored in the %RAX register, which could trigger an out-of-bounds
system call table access. An untrusted local user could exploit this
flaw to run code in the kernel (ie a root privilege escalation).
(CVE-2007-4573).

Red Hat would like to thank Wojciech Purczynski for reporting this
issue.

Red Hat Enterprise Linux 4 users are advised to upgrade to these
packages, which contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014251.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37c7987a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014264.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71eaaf4a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014265.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6d29f79"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"kernel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kernel-devel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-doc-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-doc-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"kernel-largesmp-devel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-55.0.9.EL")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-55.0.9.EL")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-devel / kernel-doc / kernel-hugemem / etc");
}
