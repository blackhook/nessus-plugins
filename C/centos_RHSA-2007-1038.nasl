#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1038 and 
# CentOS Errata and Security Advisory 2007:1038 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67060);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-5707");
  script_bugtraq_id(26245);
  script_xref(name:"RHSA", value:"2007:1038");

  script_name(english:"CentOS 4 : openldap (CESA-2007:1038)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openldap packages that fix a security flaw are now available
for Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

OpenLDAP is an open source suite of LDAP (Lightweight Directory Access
Protocol) applications and development tools.

A flaw was found in the way OpenLDAP's slapd daemon handled malformed
objectClasses LDAP attributes. An authenticated local or remote
attacker could create an LDAP request which could cause a denial of
service by crashing slapd. (CVE-2007-5707)

In addition, the following feature was added: * OpenLDAP client tools
now have new option to configure their bind timeout.

All users are advised to upgrade to these updated openldap packages,
which contain a backported patch to correct this issue and provide
this security enhancement."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-November/014432.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51e28520"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openldap packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:compat-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openldap-servers-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"compat-openldap-2.1.30-8.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-2.2.13-8.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-clients-2.2.13-8.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-devel-2.2.13-8.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-servers-2.2.13-8.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"openldap-servers-sql-2.2.13-8.c4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openldap / openldap / openldap-clients / openldap-devel / etc");
}
