#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0442 and 
# CentOS Errata and Security Advisory 2010:0442 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46763);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-1626", "CVE-2010-1848", "CVE-2010-1850");
  script_bugtraq_id(40106, 40109, 40257);
  script_xref(name:"RHSA", value:"2010:0442");

  script_name(english:"CentOS 5 : mysql (CESA-2010:0442)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mysql packages that fix three security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

MySQL is a multi-user, multi-threaded SQL database server. It consists
of the MySQL server daemon (mysqld) and many client programs and
libraries.

A buffer overflow flaw was found in the way MySQL handled the
parameters of the MySQL COM_FIELD_LIST network protocol command (this
command is sent when a client uses the MySQL mysql_list_fields()
client library function). An authenticated database user could send a
request with an excessively long table name to cause a temporary
denial of service (mysqld crash) or, potentially, execute arbitrary
code with the privileges of the database server. (CVE-2010-1850)

A directory traversal flaw was found in the way MySQL handled the
parameters of the MySQL COM_FIELD_LIST network protocol command. An
authenticated database user could use this flaw to obtain descriptions
of the fields of an arbitrary table using a request with a specially
crafted table name. (CVE-2010-1848)

A flaw was discovered in the way MySQL handled symbolic links to
tables created using the DATA DIRECTORY and INDEX DIRECTORY directives
in CREATE TABLE statements. An attacker with CREATE and DROP table
privileges, and shell access to the database server, could use this
flaw to remove data and index files of tables created by other
database users using the MyISAM storage engine. (CVE-2010-1626)

All MySQL users are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. After
installing this update, the MySQL server daemon (mysqld) will be
restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-May/016701.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c017c89"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-May/016702.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ca566f5"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mysql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"mysql-5.0.77-4.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-bench-5.0.77-4.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-devel-5.0.77-4.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-server-5.0.77-4.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mysql-test-5.0.77-4.el5_5.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql / mysql-bench / mysql-devel / mysql-server / mysql-test");
}
