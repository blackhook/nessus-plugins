#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0448. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119387);
  script_version("1.5");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2016-9587");
  script_xref(name:"RHSA", value:"2017:0448");

  script_name(english:"RHEL 7 : ansible and openshift-ansible (RHSA-2017:0448)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ansible and openshift-ansible is now available for Red
Hat OpenShift Container Platform 3.2, Red Hat OpenShift Container
Platform 3.3, and Red Hat OpenShift Container Platform 3.4.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat OpenShift Container Platform is the company's cloud computing
Platform-as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

Ansible is a SSH-based configuration management, deployment, and task
execution system. The openshift-ansible packages contain Ansible code
and playbooks for installing and upgrading OpenShift Container
Platform 3.

Security Fix(es) :

* An input validation vulnerability was found in Ansible's handling of
data sent from client systems. An attacker with control over a client
system being managed by Ansible and the ability to send facts back to
the Ansible server could use this flaw to execute arbitrary code on
the Ansible server using the Ansible server privileges.
(CVE-2016-9587)

Bug Fix(es) :

Space precludes documenting all of the non-security bug fixes in this
advisory. See the relevant OpenShift Container Platform Release Notes
linked to in the References section, which will be updated shortly for
this release."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.openshift.com/enterprise/3.2/release_notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.openshift.com/container-platform/3.3/release_notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.openshift.com/container-platform/3.4/release_notes/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:0448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-9587"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-callback-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-filter-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-lookup-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-playbooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-roles");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0448";
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
  if (rpm_check(release:"RHEL7", reference:"ansible-2.2.1.0-2.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-utils-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-utils-3.4.67-1.git.0.14a0b4d.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-3.4.67-1.git.0.14a0b4d.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-callback-plugins-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-callback-plugins-3.4.67-1.git.0.14a0b4d.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-docs-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-docs-3.4.67-1.git.0.14a0b4d.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-filter-plugins-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-filter-plugins-3.4.67-1.git.0.14a0b4d.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-lookup-plugins-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-lookup-plugins-3.4.67-1.git.0.14a0b4d.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-playbooks-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-playbooks-3.4.67-1.git.0.14a0b4d.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-roles-3.4", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-roles-3.4.67-1.git.0.14a0b4d.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ansible / atomic-openshift-utils / openshift-ansible / etc");
  }
}
