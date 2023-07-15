#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3390. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130533);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/17");

  script_cve_id("CVE-2018-15518", "CVE-2018-19870", "CVE-2018-19873");
  script_xref(name:"RHSA", value:"2019:3390");

  script_name(english:"RHEL 8 : qt5-qtbase (RHSA-2019:3390)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for qt5-qtbase is now available for Red Hat Enterprise Linux
8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Qt is a software toolkit for developing applications. The qt5-base
packages contain base tools for string, xml, and network handling in
Qt.

Security Fix(es) :

* qt5-qtbase: Double free in QXmlStreamReader (CVE-2018-15518)

* qt5-qtbase: QImage allocation failure in qgifhandler
(CVE-2018-19870)

* qt5-qtbase: QBmpHandler segmentation fault on malformed BMP file
(CVE-2018-19873)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 8.1 Release Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?774148ae"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:3390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-15518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-19870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-19873"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-assistant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-designer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-doctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-doctools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-linguist-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qdbusviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qdbusviewer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-gui-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-odbc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qtbase-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-examples-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-libs-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-libs-designer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-libs-designercomponents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-libs-designercomponents-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-libs-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-libs-help-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qt5-qttools-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3390";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-assistant-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-assistant-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-assistant-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-assistant-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-assistant-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-assistant-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-designer-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-designer-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-designer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-designer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-designer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-designer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-doctools-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-doctools-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-doctools-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-doctools-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-doctools-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-doctools-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-linguist-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-linguist-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-linguist-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-linguist-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-linguist-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-linguist-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qdbusviewer-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qdbusviewer-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qdbusviewer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qdbusviewer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qdbusviewer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qdbusviewer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"qt5-qtbase-common-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qtbase-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qtbase-debugsource-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-debugsource-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-debugsource-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-debugsource-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-devel-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-devel-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-devel-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qtbase-devel-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-devel-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-devel-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-devel-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-examples-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-examples-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-examples-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qtbase-examples-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-examples-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-examples-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-examples-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-gui-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-gui-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-gui-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qtbase-gui-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-gui-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-gui-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-gui-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-mysql-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-mysql-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-mysql-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qtbase-mysql-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-mysql-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-mysql-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-mysql-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-odbc-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-odbc-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-odbc-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qtbase-odbc-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-odbc-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-odbc-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-odbc-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-postgresql-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-postgresql-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-postgresql-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qtbase-postgresql-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-postgresql-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-postgresql-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-postgresql-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qtbase-static-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-static-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-static-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-static-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qtbase-tests-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qtbase-tests-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qtbase-tests-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qtbase-tests-debuginfo-5.11.1-7.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", reference:"qt5-qttools-common-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qttools-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qttools-debugsource-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-debugsource-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-debugsource-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-debugsource-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-devel-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-devel-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-devel-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qttools-devel-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-devel-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-devel-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-devel-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-examples-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-examples-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-examples-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qttools-examples-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-examples-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-examples-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-examples-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-libs-designer-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-libs-designer-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-libs-designer-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qttools-libs-designer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-libs-designer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-libs-designer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-libs-designer-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-libs-designercomponents-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-libs-designercomponents-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-libs-designercomponents-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qttools-libs-designercomponents-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-libs-designercomponents-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-libs-designercomponents-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-libs-designercomponents-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-libs-help-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-libs-help-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-libs-help-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qttools-libs-help-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-libs-help-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-libs-help-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-libs-help-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qttools-static-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-static-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-static-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-static-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"aarch64", reference:"qt5-qttools-tests-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"qt5-qttools-tests-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"qt5-qttools-tests-debuginfo-5.11.1-9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"qt5-qttools-tests-debuginfo-5.11.1-9.el8")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt5-assistant / qt5-assistant-debuginfo / qt5-designer / etc");
  }
}
