#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0173 and 
# CentOS Errata and Security Advisory 2014:0173 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72863);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-3839", "CVE-2013-5807", "CVE-2013-5891", "CVE-2013-5908", "CVE-2014-0001", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0420", "CVE-2014-0437");
  script_bugtraq_id(63105, 63109, 64849, 64877, 64880, 64888, 64891, 64896, 64898, 64904, 64908, 65298);
  script_xref(name:"RHSA", value:"2014:0173");

  script_name(english:"CentOS 6 : mysql55-mysql (CESA-2014:0173)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote CentOS host is missing a security update which has been
documented in Red Hat advisory RHSA-2014:0173."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-February/020165.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1718fd7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql55-mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0001");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mysql55-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mysql55-mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mysql55-mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mysql55-mysql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mysql55-mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mysql55-mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mysql55-mysql-5.5.36-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mysql55-mysql-bench-5.5.36-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mysql55-mysql-devel-5.5.36-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mysql55-mysql-libs-5.5.36-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mysql55-mysql-server-5.5.36-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mysql55-mysql-test-5.5.36-1.1.el6.centos.alt")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql55-mysql / mysql55-mysql-bench / mysql55-mysql-devel / etc");
}
