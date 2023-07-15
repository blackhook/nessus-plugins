#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2778. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119385);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/11");

  script_cve_id("CVE-2016-8628");
  script_xref(name:"RHSA", value:"2016:2778");

  script_name(english:"RHEL 7 : atomic-openshift-utils (RHSA-2016:2778)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for openshift-ansible and ansible is now available for
OpenShift Container Platform 3.2 and 3.3.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat OpenShift Container Platform is the company's cloud computing
Platform-as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

Security Fix(es) :

* Ansible fails to properly sanitize fact variables sent from the
Ansible controller. An attacker with the ability to create special
variables on the controller could execute arbitrary commands on
Ansible clients as the user Ansible runs as. (CVE-2016-8628)

This issue was discovered by Michael Scherer (Red Hat).

Bug Fix(es) :

* Previous versions of the openshift-ansible code base were not
compatible with the latest Ansible 2.2.0.0 release. This bug fix
resolves several compatibility issues with the GA version of Ansible
2.2.0.0. (BZ#1389928) (BZ#1389275)

* The hosts.ose.example inventory file had the incorrect
openshift_release version set. This bug fix updates the version to
match the channel in which it is shipped. (BZ#1386333)

* The etcd certificate authority created by the installer had an
expiry date one year in the future. With this bug fix, the expiry date
has been updated to five years, matching the lifespan of other
certificate authorities created by the installer. (BZ#1391548)

* After restarting systemd-journal, master controllers and API
services stopped working. This bug fix updates the installer to set
Restart=always for the master controllers and API services, and this
issue no longer occurs for new installations. For existing clusters,
see https:// access.redhat.com/solutions/2749571. (BZ#1378929)

* When using the quick installer to install a cluster with a single
master, the installer messaging suggested that an embedded etcd would
be deployed. In newer versions of the quick installer, this is no
longer the case, and a stand-alone etcd datastore is deployed in this
scenario. This bug fix updates the quick installer messaging to match
those changes. (BZ#1383961)

* Upgrades would fail if the /etc/ansible/facts.d/openshift.fact cache
was missing on the system, particularly for co-located master and etcd
hosts. This bug fix improves etcd fact checking during upgrades, and
the issue no longer occurs. (BZ#1391608)

* Containerized upgrades from OpenShift Container Platform 3.2 to 3.3
would fail to properly create the service signing certificate due to
an invalid path being used in containerized environments. This bug fix
corrects that error, and containerized upgrades now create service
signer certificates as a result. (BZ#1391865)

* Upgrades from OpenShift Container Platform 3.2 to 3.3 could fail
with the error 'AnsibleUndefinedVariable: 'dict object' has no
attribute 'debug_level''. This bug fix sets missing defaults for
debug_level, and as a result the upgrade error no longer occurs.
(BZ#1392276)

* Previously in embedded environments, etcd 2.x was used to backup the
etcd data before performing an upgrade. However, etcd 2.x has a bug
that prevents backups from working properly, preventing the upgrade
playbooks from running to completion. With this bug fix, etcd 3.0 is
now installed for embedded etcd environments, which resolves the bug
allowing upgrades to proceed normally. This bug only presents itself
when using the embedded etcd service on single master environments.
(BZ#1382634)

* Pacemaker clusters are no longer supported, but related code that
remained could in some cases cause upgrade failures. This bug fix
removes the Pacemaker restart logic from the installer to avoid these
issues. (BZ# 1382936)

* Previously, upgrades from OpenShift Container Platform 3.1 to 3.2
could fail due to erroneous host names being added for etcd hosts
during backup. This bug fix addresses issues with conditionals and
loops in templates that caused this problem, and as a result the
upgrade errors no longer occur. (BZ#1392169)

All OpenShift Container Platform users are advised to upgrade to these
updated packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:2778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-8628"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2016:2778";
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
  if (rpm_check(release:"RHEL7", reference:"ansible-2.2.0.0-1.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-utils-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-utils-3.3.50-1.git.0.5bdbeaa.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-3.3.50-1.git.0.5bdbeaa.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-callback-plugins-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-callback-plugins-3.3.50-1.git.0.5bdbeaa.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-docs-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-docs-3.3.50-1.git.0.5bdbeaa.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-filter-plugins-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-filter-plugins-3.3.50-1.git.0.5bdbeaa.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-lookup-plugins-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-lookup-plugins-3.3.50-1.git.0.5bdbeaa.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-playbooks-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-playbooks-3.3.50-1.git.0.5bdbeaa.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-roles-3.3", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-roles-3.3.50-1.git.0.5bdbeaa.el7")) flag++;

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
