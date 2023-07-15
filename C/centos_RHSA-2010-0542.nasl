#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0542 and 
# CentOS Errata and Security Advisory 2010:0542 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47789);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-0211", "CVE-2010-0212");
  script_bugtraq_id(41770);
  script_xref(name:"RHSA", value:"2010:0542");

  script_name(english:"CentOS 5 : openldap (CESA-2010:0542)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

Multiple flaws were discovered in the way the slapd daemon handled
modify relative distinguished name (modrdn) requests. An authenticated
user with privileges to perform modrdn operations could use these
flaws to crash the slapd daemon via specially crafted modrdn requests.
(CVE-2010-0211, CVE-2010-0212)

Red Hat would like to thank CERT-FI for responsibly reporting these
flaws, who credit Ilkka Mattila and Tuomas Salomaki for the discovery
of the issues.

Users of OpenLDAP should upgrade to these updated packages, which
contain a backported patch to correct these issues. After installing
this update, the OpenLDAP daemons will be restarted automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016817.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bae158a8"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-July/016818.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34eae7ea"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-overlays");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/22");
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
if (rpm_check(release:"CentOS-5", reference:"compat-openldap-2.3.43_2.2.29-12.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-2.3.43-12.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-clients-2.3.43-12.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-devel-2.3.43-12.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-2.3.43-12.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-overlays-2.3.43-12.el5_5.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openldap-servers-sql-2.3.43-12.el5_5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-devel / etc");
}
