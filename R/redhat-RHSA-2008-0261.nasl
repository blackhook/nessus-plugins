#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0261. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43835);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2004-0885", "CVE-2005-0605", "CVE-2005-2090", "CVE-2005-3510", "CVE-2005-3964", "CVE-2005-4838", "CVE-2006-0254", "CVE-2006-0898", "CVE-2006-1329", "CVE-2006-3835", "CVE-2006-5752", "CVE-2006-7195", "CVE-2006-7196", "CVE-2006-7197", "CVE-2007-0243", "CVE-2007-0450", "CVE-2007-1349", "CVE-2007-1355", "CVE-2007-1358", "CVE-2007-1860", "CVE-2007-2435", "CVE-2007-2449", "CVE-2007-2450", "CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3304", "CVE-2007-3382", "CVE-2007-3385", "CVE-2007-4465", "CVE-2007-5000", "CVE-2007-5461", "CVE-2007-5961", "CVE-2007-6306", "CVE-2007-6388", "CVE-2008-0128");
  script_bugtraq_id(15325, 16802, 19106, 22085, 22960, 23192, 24004, 24147, 24215, 24475, 24476, 24524, 24645, 25316, 25531, 25653, 26070, 26752, 26838, 27237, 27365, 28481);
  script_xref(name:"RHSA", value:"2008:0261");

  script_name(english:"RHEL 4 : Satellite Server (RHSA-2008:0261)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Network Satellite Server version 5.0.2 is now available. This
update includes fixes for a number of security issues in Red Hat
Network Satellite Server components.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

During an internal security review, a cross-site scripting flaw was
found that affected the Red Hat Network channel search feature.
(CVE-2007-5961)

This release also corrects several security vulnerabilities in various
components shipped as part of the Red Hat Network Satellite Server. In
a typical operating environment, these components are not exposed to
users of Satellite Server in a vulnerable manner. These security
updates will reduce risk in unique Satellite Server environments.

Multiple flaws were fixed in the Apache HTTPD server. These flaws
could result in a cross-site scripting, denial-of-service, or
information disclosure attacks. (CVE-2004-0885, CVE-2006-5752,
CVE-2006-7197, CVE-2007-1860, CVE-2007-3304, CVE-2007-4465,
CVE-2007-5000, CVE-2007-6388)

A denial-of-service flaw was fixed in mod_perl. (CVE-2007-1349)

A denial-of-service flaw was fixed in the jabberd server.
(CVE-2006-1329)

Multiple cross-site scripting flaws were fixed in the image map
feature in the JFreeChart package. (CVE-2007-6306)

Multiple flaws were fixed in the IBM Java 1.4.2 Runtime.
(CVE-2007-0243, CVE-2007-2435, CVE-2007-2788, CVE-2007-2789)

Two arbitrary code execution flaws were fixed in the OpenMotif
package. (CVE-2005-3964, CVE-2005-0605)

A flaw which could result in weak encryption was fixed in the
perl-Crypt-CBC package. (CVE-2006-0898)

Multiple flaws were fixed in the Tomcat package. (CVE-2008-0128,
CVE-2007-5461, CVE-2007-3385, CVE-2007-3382, CVE-2007-1358,
CVE-2007-1355, CVE-2007-2450, CVE-2007-2449, CVE-2007-0450,
CVE-2006-7196, CVE-2006-7195, CVE-2006-3835, CVE-2006-0254,
CVE-2005-2090, CVE-2005-4838, CVE-2005-3510)

Users of Red Hat Network Satellite Server 5.0 are advised to upgrade
to 5.0.2, which resolves these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2004-0885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-0605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-2090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-3964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2005-4838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-0254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-0898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-1329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-3835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-5752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-7195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-7196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2006-7197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-0243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-0450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-1349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-1355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-1358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-1860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-2435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-2449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-2450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-2788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-2789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-3304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-3382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-3385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-4465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-5000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-5461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-5961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-6306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-6388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-0128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2008:0261"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 22, 79, 119, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jabberd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jfreechart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openmotif21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Crypt-CBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhn-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhn-modjk-ap13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhn-modperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhn-modssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0261";
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

  if (! (rpm_exists(release:"RHEL4", rpm:"rhns-app-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"jabberd-2.0s10-3.38.rhn")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.4.2-ibm-1.4.2.10-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"java-1.4.2-ibm-devel-1.4.2.10-1jpp.2.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jfreechart-0.9.20-3.rhn")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openmotif21-2.1.30-11.RHEL4.6")) flag++;
  if (rpm_check(release:"RHEL4", reference:"perl-Crypt-CBC-2.24-1.el4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"rhn-apache-1.3.27-36.rhn.rhel4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"rhn-modjk-ap13-1.2.23-2rhn.rhel4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"rhn-modperl-1.29-16.rhel4")) flag++;
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"rhn-modssl-2.8.12-8.rhn.10.rhel4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"tomcat5-5.0.30-0jpp_10rh")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jabberd / java-1.4.2-ibm / java-1.4.2-ibm-devel / jfreechart / etc");
  }
}
