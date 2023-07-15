#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0005. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105522);
  script_version("3.15");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2016-6346", "CVE-2017-12165", "CVE-2017-12167", "CVE-2017-12189", "CVE-2017-12629", "CVE-2017-7559", "CVE-2017-7561");
  script_xref(name:"RHSA", value:"2018:0005");
  script_xref(name:"IAVA", value:"2017-A-0319");

  script_name(english:"RHEL 6 / 7 : eap7-jboss-ec2-eap (RHSA-2018:0005)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for eap7-jboss-ec2-eap is now available for Red Hat JBoss
Enterprise Application Platform 7.0 for Red Hat Enterprise Linux 6 and
Red Hat JBoss Enterprise Application Platform 7.0 for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The eap7-jboss-ec2-eap packages provide scripts for Red Hat JBoss
Enterprise Application Platform running on the Amazon Web Services
(AWS) Elastic Compute Cloud (EC2).

With this update, the eap7-jboss-ec2-eap package has been updated to
ensure compatibility with Red Hat JBoss Enterprise Application
Platform 7.0.9.

Refer to the JBoss Enterprise Application Platform 7.0.9 Release
Notes, linked to in the References section, for information on the
most significant bug fixes and enhancements included in this release.

Security Fix(es) :

* It was found that Apache Lucene would accept an object from an
unauthenticated user that could be manipulated through subsequent post
requests. An attacker could use this flaw to assemble an object that
could permit execution of arbitrary code if the server enabled Apache
Solr's Config API. (CVE-2017-12629)

* It was discovered that the jboss init script performed unsafe file
handling which could result in local privilege escalation.
(CVE-2017-12189)

* It was found that GZIPInterceptor is enabled when not necessarily
required in RESTEasy. An attacker could use this flaw to launch a
Denial of Service attack. (CVE-2016-6346)

* It was found that the fix for CVE-2017-2666 was incomplete and
invalid characters are still allowed in the query string and path
parameters. This could be exploited, in conjunction with a proxy that
also permitted the invalid characters but with a different
interpretation, to inject data into the HTTP response. By manipulating
the HTTP response the attacker could poison a web-cache, perform an
XSS attack, or obtain sensitive information from requests other than
their own. (CVE-2017-7559)

* It was discovered that the CORS Filter did not add an HTTP Vary
header indicating that the response varies depending on Origin. This
permitted client and server side cache poisoning in some
circumstances. (CVE-2017-7561)

* It was found that properties based files of the management and the
application realm configuration that contain user to role mapping are
world readable allowing access to users and roles information to all
the users logged in to the system. (CVE-2017-12167)

* It was discovered that Undertow processes http request headers with
unusual whitespaces which can cause possible http request smuggling.
(CVE-2017-12165)

Red Hat would like to thank Mikhail Egorov (Odin) for reporting
CVE-2016-6346. The CVE-2017-7559 and CVE-2017-12165 issues were
discovered by Stuart Douglas (Red Hat); the CVE-2017-7561 issue was
discovered by Jason Shepherd (Red Hat Product Security); and the
CVE-2017-12167 issue was discovered by Brian Stansberry (Red Hat) and
Jeremy Choi (Red Hat)."
  );
  # https://access.redhat.com/documentation/en/
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-us/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:0005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-12629"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected eap7-jboss-ec2-eap and / or
eap7-jboss-ec2-eap-samples packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ec2-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:eap7-jboss-ec2-eap-samples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2018:0005";
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
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-ec2-eap-7.0.9-2.GA_redhat_2.ep7.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"eap7-jboss-ec2-eap-samples-7.0.9-2.GA_redhat_2.ep7.el6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-ec2-eap-7.0.9-2.GA_redhat_2.ep7.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"eap7-jboss-ec2-eap-samples-7.0.9-2.GA_redhat_2.ep7.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eap7-jboss-ec2-eap / eap7-jboss-ec2-eap-samples");
  }
}
