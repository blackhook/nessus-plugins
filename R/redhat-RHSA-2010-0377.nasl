#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0377. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63929);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id("CVE-2010-0738", "CVE-2010-1428", "CVE-2010-1429");
  script_xref(name:"RHSA", value:"2010:0377");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"RHEL 4 : JBoss EAP (RHSA-2010:0377)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated JBoss Enterprise Application Platform (JBEAP) 4.3 packages
that fix three security issues and multiple bugs are now available for
Red Hat Enterprise Linux 4 as JBEAP 4.3.0.CP08.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

JBoss Enterprise Application Platform is the market leading platform
for innovative and scalable Java applications; integrating the JBoss
Application Server, with JBoss Hibernate and JBoss Seam into a
complete, simple enterprise solution.

This release of JBEAP for Red Hat Enterprise Linux 4 serves as a
replacement to JBEAP 4.3.0.CP07.

These updated packages include multiple bug fixes which are detailed
in the Release Notes. The Release Notes will be available shortly from
the link in the References section.

The following security issues are also fixed with this release :

The JMX Console configuration only specified an authentication
requirement for requests that used the GET and POST HTTP 'verbs'. A
remote attacker could create an HTTP request that does not specify GET
or POST, causing it to be executed by the default GET handler without
authentication. This release contains a JMX Console with an updated
configuration that no longer specifies the HTTP verbs. This means that
the authentication requirement is applied to all requests.
(CVE-2010-0738)

For the CVE-2010-0738 issue, if an immediate upgrade is not possible
or the server deployment has been customized, a manual fix can be
applied. Refer to the 'Security' subsection of the 'Issues fixed in
this release' section (JBPAPP-3952) of the JBEAP Release Notes, linked
to in the References, for details. Contact Red Hat JBoss Support for
advice before making the changes noted in the Release Notes.

Red Hat would like to thank Stefano Di Paola and Giorgio Fedon of
Minded Security for responsibly reporting the CVE-2010-0738 issue.

Unauthenticated access to the JBoss Application Server Web Console
(/web-console) is blocked by default. However, it was found that this
block was incomplete, and only blocked GET and POST HTTP verbs. A
remote attacker could use this flaw to gain access to sensitive
information. This release contains a Web Console with an updated
configuration that now blocks all unauthenticated access to it by
default. (CVE-2010-1428)

The RHSA-2008:0826 update fixed an issue (CVE-2008-3273) where
unauthenticated users were able to access the status servlet; however,
a bug fix included in the RHSA-2009:0347 update re-introduced the
issue. A remote attacker could use this flaw to acquire details about
deployed web contexts. (CVE-2010-1429)

Warning: Before applying this update, please backup the JBEAP
'server/[configuration]/deploy/' directory, and any other customized
configuration files.

All users of JBEAP 4.3 on Red Hat Enterprise Linux 4 are advised to
upgrade to these updated packages.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0738");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-1428");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-1429");
  # http://www.redhat.com/docs/en-US/JBoss_Enterprise_Application_Platform/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13c46bfa");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0377");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1429");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'JBoss JMX Console Deployer Upload and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-132");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-annotations-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hibernate3-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hsqldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jacorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jakarta-commons-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-aop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-remoting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-seam2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-4.3.0.GA_CP08-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossas-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jbossws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rh-eap-docs-examples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2010:0377";
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

  if (! (rpm_exists(release:"RHEL4", rpm:"jbossas-client-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL4", reference:"hibernate3-3.2.4-1.SP1_CP10.0jpp.ep1.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-annotations-3.3.1-1.12.GA_CP03.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-annotations-javadoc-3.3.1-1.12.GA_CP03.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hibernate3-javadoc-3.2.4-1.SP1_CP10.0jpp.ep1.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"hsqldb-1.8.0.8-3.patch03.1jpp.ep1.3.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jacorb-2.3.0-1jpp.ep1.10.el4")) flag++;
  if (rpm_exists(rpm:"jakarta-commons-httpclient-3.0.1-1", release:"RHEL4") && rpm_check(release:"RHEL4", reference:"jakarta-commons-httpclient-3.0.1-1.patch01.1jpp.ep1.4.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-aop-1.5.5-3.CP05.2.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-cache-1.4.1-6.SP14.1.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-messaging-1.4.0-3.SP3_CP10.2.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-remoting-2.2.3-3.SP2.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam-1.2.1-3.JBPAPP_4_3_0_GA.ep1.20.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam-docs-1.2.1-3.JBPAPP_4_3_0_GA.ep1.20.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-2.0.2.FP-1.ep1.23.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jboss-seam2-docs-2.0.2.FP-1.ep1.23.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-4.3.0-7.GA_CP08.5.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-4.3.0.GA_CP08-bin-4.3.0-7.GA_CP08.5.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossas-client-4.3.0-7.GA_CP08.5.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossts-4.2.3-1.SP5_CP09.1jpp.ep1.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossweb-2.0.0-6.CP13.0jpp.ep1.1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"jbossws-2.0.1-5.SP2_CP08.1.ep1.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rh-eap-docs-4.3.0-7.GA_CP08.ep1.6.el4")) flag++;
  if (rpm_check(release:"RHEL4", reference:"rh-eap-docs-examples-4.3.0-7.GA_CP08.ep1.6.el4")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hibernate3 / hibernate3-annotations / etc");
  }
}
