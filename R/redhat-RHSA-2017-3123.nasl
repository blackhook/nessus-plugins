#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3123. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104457);
  script_version("3.12");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-12629");
  script_xref(name:"RHSA", value:"2017:3123");
  script_xref(name:"IAVA", value:"2017-A-0319");

  script_name(english:"RHEL 6 / 7 : JBoss EAP (RHSA-2017:3123)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security update is now available for Red Hat JBoss Enterprise
Application Platform 7 for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

[Updated 6th November 2017] Previously, this erratum was marked as
having a security impact of Critical. This was incorrect; Red Hat
JBoss Enterprise Application Platform 7 was affected with a security
impact of Moderate. This advisory has been updated to that effect.

Red Hat JBoss Enterprise Application Platform is a platform for Java
applications based on the JBoss Application Server.

This asynchronous patch is a security update for lucene package in Red
Hat JBoss Enterprise Application Platform 7.0.8.

Security Fix(es) :

* It was found that Apache Lucene would accept an object from an
unauthenticated user that could be manipulated through subsequent post
requests. An attacker could use this flaw to assemble an object that
could permit execution of arbitrary code if the server enabled Apache
Solr's Config API. (CVE-2017-12629)

For more information regarding CVE-2017-12629, see the article linked
in the references section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/CVE-2017-12629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:3123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12629"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-analyzers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-backward-codecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-facet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-queries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-queryparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-lucene-solr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:3123";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"jbossas-welcome-content-eap") || rpm_exists(release:"RHEL7", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL6", reference:"eap7-lucene-analyzers-common-5.3.1-4.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-lucene-backward-codecs-5.3.1-4.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-lucene-core-5.3.1-4.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-lucene-facet-5.3.1-4.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-lucene-misc-5.3.1-4.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-lucene-queries-5.3.1-4.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-lucene-queryparser-5.3.1-4.redhat_2.1.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-lucene-solr-5.3.1-4.redhat_2.1.ep7.el6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"eap7-lucene-analyzers-common-5.3.1-4.redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-lucene-backward-codecs-5.3.1-4.redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-lucene-core-5.3.1-4.redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-lucene-facet-5.3.1-4.redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-lucene-misc-5.3.1-4.redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-lucene-queries-5.3.1-4.redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-lucene-queryparser-5.3.1-4.redhat_2.1.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-lucene-solr-5.3.1-4.redhat_2.1.ep7.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eap7-lucene-analyzers-common / eap7-lucene-backward-codecs / etc");
  }
}
