#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1840. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86200);
  script_version("2.15");
  script_cvs_date("Date: 2019/10/24 15:35:40");

  script_cve_id("CVE-2015-6908");
  script_xref(name:"RHSA", value:"2015:1840");

  script_name(english:"RHEL 5 / 6 / 7 : openldap (RHSA-2015:1840)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix one security issue are now
available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

OpenLDAP is an open source suite of Lightweight Directory Access
Protocol (LDAP) applications and development tools. LDAP is a set of
protocols used to access and maintain distributed directory
information services over an IP network. The openldap package contains
configuration files, libraries, and documentation for OpenLDAP.

A flaw was found in the way the OpenLDAP server daemon (slapd) parsed
certain Basic Encoding Rules (BER) data. A remote attacker could use
this flaw to crash slapd via a specially crafted packet.
(CVE-2015-6908)

All openldap users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:1840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-6908"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers-overlays");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1840";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL5", reference:"compat-openldap-2.3.43_2.2.29-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", reference:"openldap-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openldap-clients-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openldap-clients-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openldap-clients-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", reference:"openldap-debuginfo-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", reference:"openldap-devel-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openldap-servers-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openldap-servers-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openldap-servers-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openldap-servers-overlays-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openldap-servers-overlays-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openldap-servers-overlays-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openldap-servers-sql-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openldap-servers-sql-2.3.43-29.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openldap-servers-sql-2.3.43-29.el5_11")) flag++;


  if (rpm_check(release:"RHEL6", reference:"openldap-2.4.40-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openldap-clients-2.4.40-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openldap-clients-2.4.40-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openldap-clients-2.4.40-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openldap-debuginfo-2.4.40-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openldap-devel-2.4.40-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openldap-servers-2.4.40-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openldap-servers-2.4.40-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openldap-servers-2.4.40-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openldap-servers-sql-2.4.40-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openldap-servers-sql-2.4.40-6.el6_7")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openldap-servers-sql-2.4.40-6.el6_7")) flag++;


  if (rpm_check(release:"RHEL7", reference:"openldap-2.4.39-7.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openldap-clients-2.4.39-7.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openldap-clients-2.4.39-7.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openldap-debuginfo-2.4.39-7.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openldap-devel-2.4.39-7.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openldap-servers-2.4.39-7.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openldap-servers-2.4.39-7.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openldap-servers-sql-2.4.39-7.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openldap-servers-sql-2.4.39-7.el7_1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-debuginfo / etc");
  }
}
