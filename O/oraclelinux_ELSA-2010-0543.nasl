#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0543 and 
# Oracle Linux Security Advisory ELSA-2010-0543 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68065);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-3767", "CVE-2010-0211");
  script_bugtraq_id(36844, 41770);
  script_xref(name:"RHSA", value:"2010:0543");

  script_name(english:"Oracle Linux 4 : openldap (ELSA-2010-0543)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0543 :

Updated openldap packages that fix two security issues are now
available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

An uninitialized pointer use flaw was discovered in the way the slapd
daemon handled modify relative distinguished name (modrdn) requests.
An authenticated user with privileges to perform modrdn operations
could use this flaw to crash the slapd daemon via specially crafted
modrdn requests. (CVE-2010-0211)

Red Hat would like to thank CERT-FI for responsibly reporting the
CVE-2010-0211 flaw, who credit Ilkka Mattila and Tuomas Salomaki for
the discovery of the issue.

A flaw was found in the way OpenLDAP handled NUL characters in the
CommonName field of X.509 certificates. An attacker able to get a
carefully-crafted certificate signed by a trusted Certificate
Authority could trick applications using OpenLDAP libraries into
accepting it by mistake, allowing the attacker to perform a
man-in-the-middle attack. (CVE-2009-3767)

Users of OpenLDAP should upgrade to these updated packages, which
contain backported patches to resolve these issues. After installing
this update, the OpenLDAP daemons will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-July/001543.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/20");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"compat-openldap-2.1.30-12.el4_8.3")) flag++;
if (rpm_check(release:"EL4", reference:"openldap-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"EL4", reference:"openldap-clients-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"EL4", reference:"openldap-devel-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"EL4", reference:"openldap-servers-2.2.13-12.el4_8.3")) flag++;
if (rpm_check(release:"EL4", reference:"openldap-servers-sql-2.2.13-12.el4_8.3")) flag++;


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
