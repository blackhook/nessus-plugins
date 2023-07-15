#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1840 and 
# Oracle Linux Security Advisory ELSA-2015-1840 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86199);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-6908");
  script_xref(name:"RHSA", value:"2015:1840");

  script_name(english:"Oracle Linux 5 / 6 / 7 : openldap (ELSA-2015-1840)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1840 :

Updated openldap packages that fix one security issue are now
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
    value:"https://oss.oracle.com/pipermail/el-errata/2015-September/005434.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-September/005435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-September/005436.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-servers-overlays");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"compat-openldap-2.3.43_2.2.29-29.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-clients-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-devel-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-servers-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-servers-overlays-2.3.43-29.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"openldap-servers-sql-2.3.43-29.el5_11")) flag++;

if (rpm_check(release:"EL6", reference:"openldap-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"openldap-clients-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"openldap-devel-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"openldap-servers-2.4.40-6.el6_7")) flag++;
if (rpm_check(release:"EL6", reference:"openldap-servers-sql-2.4.40-6.el6_7")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openldap-2.4.39-7.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openldap-clients-2.4.39-7.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openldap-devel-2.4.39-7.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openldap-servers-2.4.39-7.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openldap-servers-sql-2.4.39-7.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-devel / etc");
}