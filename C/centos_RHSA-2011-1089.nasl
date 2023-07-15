#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1089 and 
# CentOS Errata and Security Advisory 2011:1089 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56267);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-2503");
  script_xref(name:"RHSA", value:"2011:1089");

  script_name(english:"CentOS 5 : systemtap (CESA-2011:1089)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated systemtap packages that fix one security issue are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

SystemTap is an instrumentation system for systems running the Linux
kernel. The system allows developers to write scripts to collect data
on the operation of the system.

A race condition flaw was found in the way the staprun utility
performed module loading. A local user who is a member of the stapusr
group could use this flaw to modify a signed module while it is being
loaded, allowing them to escalate their privileges. (CVE-2011-2503)

SystemTap users should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017996.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0ac8a6a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017998.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dcb9206a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000290.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?137dd53c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000291.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?270105f6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemtap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-initscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-sdt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/26");
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
if (rpm_check(release:"CentOS-5", reference:"systemtap-1.3-9.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-client-1.3-9.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-initscript-1.3-9.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-runtime-1.3-9.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-sdt-devel-1.3-9.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-server-1.3-9.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-testsuite-1.3-9.el5")) flag++;


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
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemtap / systemtap-client / systemtap-initscript / etc");
}
