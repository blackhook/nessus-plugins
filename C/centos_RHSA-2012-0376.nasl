#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0376 and 
# CentOS Errata and Security Advisory 2012:0376 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58294);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-0875");
  script_bugtraq_id(52121);
  script_xref(name:"RHSA", value:"2012:0376");

  script_name(english:"CentOS 5 / 6 : systemtap (CESA-2012:0376)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated systemtap packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

SystemTap is an instrumentation system for systems running the Linux
kernel. The system allows developers to write scripts to collect data
on the operation of the system.

An invalid pointer read flaw was found in the way SystemTap handled
malformed debugging information in DWARF format. When SystemTap
unprivileged mode was enabled, an unprivileged user in the stapusr
group could use this flaw to crash the system or, potentially, read
arbitrary kernel memory. Additionally, a privileged user (root, or a
member of the stapdev group) could trigger this flaw when tricked into
instrumenting a specially crafted ELF binary, even when unprivileged
mode was not enabled. (CVE-2012-0875)

SystemTap users should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-March/018485.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb58dfe9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2012-March/018487.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16479c55"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemtap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0875");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-grapher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-initscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-sdt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:systemtap-testsuite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/09");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"systemtap-1.6-7.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-initscript-1.6-7.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-runtime-1.6-7.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-sdt-devel-1.6-7.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-server-1.6-7.el5_8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"systemtap-testsuite-1.6-7.el5_8")) flag++;

if (rpm_check(release:"CentOS-6", reference:"systemtap-1.6-5.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"systemtap-grapher-1.6-5.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"systemtap-initscript-1.6-5.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"systemtap-runtime-1.6-5.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"systemtap-sdt-devel-1.6-5.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"systemtap-server-1.6-5.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"systemtap-testsuite-1.6-5.el6_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemtap / systemtap-grapher / systemtap-initscript / etc");
}
