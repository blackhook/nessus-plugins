#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1244. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119388);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id("CVE-2017-7466", "CVE-2017-7481");
  script_xref(name:"RHSA", value:"2017:1244");

  script_name(english:"RHEL 7 : ansible and openshift-ansible (RHSA-2017:1244)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for ansible and openshift-ansible is now available for Red
Hat OpenShift Container Platform 3.2, Red Hat OpenShift Container
Platform 3.3, Red Hat OpenShift Container Platform 3.4, and Red Hat
OpenShift Container Platform 3.5.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Ansible is a simple model-driven configuration management, multi-node
deployment, and remote task execution system. Ansible works over SSH
and does not require any software or daemons to be installed on remote
nodes.

The openshift-ansible packages contain Ansible code and playbooks for
installing and upgrading OpenShift Container Platform 3.

Security Fix(es) :

* An input validation vulnerability was found in Ansible's handling of
data sent from client systems. An attacker with control over a client
system being managed by Ansible, and the ability to send facts back to
the Ansible server, could use this flaw to execute arbitrary code on
the Ansible server using the Ansible server privileges.
(CVE-2017-7466)

* An input validation flaw was found in Ansible, where it fails to
properly mark lookup-plugin results as unsafe. If an attacker could
control the results of lookup() calls, they could inject Unicode
strings to be parsed by the jinja2 templating system, resulting in
code execution. By default, the jinja2 templating language is now
marked as 'unsafe' and is not evaluated. (CVE-2017-7481)

These issues were discovered by Evgeni Golov (Red Hat).

Bug Fix(es) :

* The installer could fail to add iptables rules if other iptables
rules were updated at the same time. The installer now waits to obtain
a lock, ensuring that rules are properly created. (BZ#1445194,
BZ#1445282)

* In multi-master environments, if `ansible_host` and
`openshift_hostname` values differ and Ansible sorts one of the lists
differently from the other, the CA host may be the first master but it
was still signing the initial certificates with the host names of the
first master. By ensuring that the host names of the CA host are used
when creating the certificate authority, this bug fix ensures that
certificates are signed with correct host names. (BZ#1447399,
BZ#1440309, BZ#1447398)

* Running Ansible via `batch` systems like the `nohup` command caused
Ansible to leak file descriptors and abort playbooks whenever the
maximum number of open file descriptors was reached. Ansible 2.2.3.0
includes a fix for this problem, and OCP channels have been updated to
include this version. (BZ# 1439277)

* The OCP 3.4 logging stack upgraded the schema to use the common
standard logging data model. However, some of the Elasticsearch and
Kibana configuration using this schema was missing, causing Kibana to
show an error message upon startup. The correct Elasticsearch and
Kibana configuration is now added to the logging stack, including for
upgrades from OCP 3.3 to 3.4, and from 3.4.x to 3.4.y. As a result,
Kibana works correctly with the new logging data schema. (BZ#1444106)

* Because the upgrade playbooks upgraded packages in a serial manner
rather than all at once, yum dependency resolution installed the
latest version available in the enabled repositories rather than the
requested version. This bug fix updates the playbooks to upgrade all
packages to the requested version at once, which prevents yum from
potentially upgrading to the latest version. (BZ#1391325, BZ#1449220,
BZ#1449221)

* In an environment utilizing mixed containerized and RPM-based
installation methods, the installer failed to gather facts when a
master and node used different installation methods. This bug fix
updates the installer to ensure mixed installations work properly.
(BZ#1408663)

* Previously, if `enable_excluders=false` was set, playbooks still
installed and upgraded the excluders during the config.yml playbook
even if the excluders were never previously installed. With this bug
fix, if the excluders were not previously installed, playbooks avoid
installing them. (BZ#1434679)

* Previously, playbooks aborted if a namespace had non-ASCII
characters in their descriptions. This bug fix updates playbooks to
properly decode Unicode characters, ensuring that upgrades to OCP 3.5
work as expected. (BZ #1444806)");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2017:1244");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-7466");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2017-7481");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7466");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7481");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

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
  rhsa = "RHSA-2017:1244";
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
  if (rpm_check(release:"RHEL7", reference:"ansible-2.2.3.0-1.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-utils-3.5", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-utils-3.5.71-1.git.0.128c2db.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-3.5", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-3.5.71-1.git.0.128c2db.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-callback-plugins-3.5", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-callback-plugins-3.5.71-1.git.0.128c2db.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-docs-3.5", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-docs-3.5.71-1.git.0.128c2db.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-filter-plugins-3.5", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-filter-plugins-3.5.71-1.git.0.128c2db.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-lookup-plugins-3.5", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-lookup-plugins-3.5.71-1.git.0.128c2db.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-playbooks-3.5", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-playbooks-3.5.71-1.git.0.128c2db.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-roles-3.5", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-roles-3.5.71-1.git.0.128c2db.el7")) flag++;

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
