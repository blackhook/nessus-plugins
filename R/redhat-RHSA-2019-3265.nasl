#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3265. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130418);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-9512", "CVE-2019-9514");
  script_xref(name:"RHSA", value:"2019:3265");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"RHEL 7 : OpenShift Container Platform 4.1 (RHSA-2019:3265) (Ping Flood) (Reset Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update is now available for Red Hat OpenShift Container Platform
4.1.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat OpenShift Container Platform is Red Hat's cloud computing
Kubernetes application platform solution designed for on-premise or
private cloud deployments.

This advisory contains the ansible-operator, apb,
containernetworking-plugins,
golang-github-openshift-prometheus-alert-buffer,
golang-github-prometheus-promu and openshift-eventrouter RPM packages
for Red Hat OpenShift Container Platform 4.1.21. These packages have
been rebuilt with an updated version of Go to address the below
security issues.

Security Fix(es) :

* HTTP/2: flood using PING frames results in unbounded memory growth
(CVE-2019-9512)

* HTTP/2: flood using HEADERS frames results in unbounded memory
growth (CVE-2019-9514)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3265");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9512");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9514");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-operator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-operator-container-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-operator-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apb-container-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-openshift-prometheus-alert-buffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-prometheus-promu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-eventrouter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-eventrouter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prometheus-promu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2019:3265";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ansible-operator-0.0.1-3.git.59.4beb3d2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ansible-operator-container-scripts-0.0.1-3.git.59.4beb3d2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ansible-operator-devel-0.0.1-3.git.59.4beb3d2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"apb-2.0.3-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"apb-container-scripts-2.0.3-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"apb-devel-2.0.3-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"containernetworking-plugins-0.8.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"containernetworking-plugins-debuginfo-0.8.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"golang-github-openshift-prometheus-alert-buffer-0-3.gitceca8c1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"golang-github-prometheus-promu-0-5.git85ceabc.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-eventrouter-0.2-3.gited73fb6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-eventrouter-debuginfo-0.2-3.gited73fb6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"prometheus-promu-0-5.git85ceabc.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ansible-operator / ansible-operator-container-scripts / etc");
  }
}
