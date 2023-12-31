#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1206. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119375);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/01");

  script_cve_id(
    "CVE-2016-3721",
    "CVE-2016-3722",
    "CVE-2016-3723",
    "CVE-2016-3724",
    "CVE-2016-3725",
    "CVE-2016-3726",
    "CVE-2016-3727"
  );
  script_xref(name:"RHSA", value:"2016:1206");

  script_name(english:"RHEL 7 : jenkins (RHSA-2016:1206)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An updated Jenkins package and image that includes security fixes are
now available for Red Hat OpenShift Enterprise 3.2.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenShift Enterprise by Red Hat is the company's cloud computing
Platform- as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

Jenkins is a continuous integration server that monitors executions of
repeated jobs, such as building a software project or jobs run by
cron.

Security Fix(es) :

* The Jenkins continuous integration server has been updated to
upstream version 1.651.2 LTS that addresses a large number of security
issues, including open redirects, a potential denial of service,
unsafe handling of user provided environment variables and several
instances of sensitive information disclosure. (CVE-2016-3721,
CVE-2016-3722, CVE-2016-3723, CVE-2016-3724, CVE-2016-3725,
CVE-2016-3726, CVE-2016-3727)

Refer to the changelog listed in the References section for a list of
changes.

This update includes the following image :

openshift3/jenkins-1-rhel7:1.651.2-4

All OpenShift Enterprise 3.2 users are advised to upgrade to the
updated package and image.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:1206");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3721");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3722");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3723");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3724");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3725");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3726");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-3727");
  script_set_attribute(attribute:"solution", value:
"Update the affected jenkins and / or jenkins-plugin-openshift-pipeline
packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3726");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-plugin-openshift-pipeline");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1206";
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
  if (rpm_check(release:"RHEL7", reference:"jenkins-1.651.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"jenkins-plugin-openshift-pipeline-1.0.12-1.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jenkins / jenkins-plugin-openshift-pipeline");
  }
}
