#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1245 and 
# Oracle Linux Security Advisory ELSA-2011-1245 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68342);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-3192");
  script_bugtraq_id(49303);
  script_xref(name:"RHSA", value:"2011:1245");

  script_name(english:"Oracle Linux 4 / 5 / 6 : httpd (ELSA-2011-1245)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1245 :

Updated httpd packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Apache HTTP Server is a popular web server.

A flaw was found in the way the Apache HTTP Server handled Range HTTP
headers. A remote attacker could use this flaw to cause httpd to use
an excessive amount of memory and CPU time via HTTP requests with a
specially crafted Range header. (CVE-2011-3192)

All httpd users should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-September/002324.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-September/002327.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-September/002330.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"httpd-2.0.52-48.ent.0.1")) flag++;
if (rpm_check(release:"EL4", reference:"httpd-devel-2.0.52-48.ent.0.1")) flag++;
if (rpm_check(release:"EL4", reference:"httpd-manual-2.0.52-48.ent.0.1")) flag++;
if (rpm_check(release:"EL4", reference:"httpd-suexec-2.0.52-48.ent.0.1")) flag++;
if (rpm_check(release:"EL4", reference:"mod_ssl-2.0.52-48.ent.0.1")) flag++;

if (rpm_check(release:"EL5", reference:"httpd-2.2.3-53.0.1.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"httpd-devel-2.2.3-53.0.1.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"httpd-manual-2.2.3-53.0.1.el5_7.1")) flag++;
if (rpm_check(release:"EL5", reference:"mod_ssl-2.2.3-53.0.1.el5_7.1")) flag++;

if (rpm_check(release:"EL6", reference:"httpd-2.2.15-9.0.1.el6_1.2")) flag++;
if (rpm_check(release:"EL6", reference:"httpd-devel-2.2.15-9.0.1.el6_1.2")) flag++;
if (rpm_check(release:"EL6", reference:"httpd-manual-2.2.15-9.0.1.el6_1.2")) flag++;
if (rpm_check(release:"EL6", reference:"httpd-tools-2.2.15-9.0.1.el6_1.2")) flag++;
if (rpm_check(release:"EL6", reference:"mod_ssl-2.2.15-9.0.1.el6_1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-suexec / httpd-tools / etc");
}
