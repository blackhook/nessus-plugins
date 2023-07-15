#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1853. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119381);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/11");

  script_cve_id("CVE-2016-5418");
  script_xref(name:"RHSA", value:"2016:1853");

  script_name(english:"RHEL 7 : Red Hat OpenShift Enterprise 3.2 (RHSA-2016:1853)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for atomic-openshift and heapster is now available for Red
Hat OpenShift Enterprise 3.2.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenShift Enterprise by Red Hat is the company's cloud computing
Platform- as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

Security Fix(es) :

* When processing an archive file that contains an archive entry with
type 1 (hardlink) but also having a non-zero data size a file
overwrite can occur. This would allow an attacker that can pass data
to an application that uses libarchive to unpack it to overwrite
arbitrary files with arbitrary data. (CVE-2016-5418)

Red Hat would like to thank Insomnia Security for reporting this
issue.

This update also fixes the following bugs :

* Previously, pods that had a resource request of 0 and specified
limits were classified as BestEffort when they should have been
classified as Burstable. This bug fix ensures that those pods are
correctly classified as Burstable.(BZ#1357475)

* Future versions of docker will require containerized installations
of OpenShift Container Platform to mount /var/lib/origin with the
`rslave` flag. New installations of OpenShift Container Platform 3.2
have this value set. However, upgrades from 3.1 did not properly set
this value. This bug fix ensures that this flag is now set during
upgrades, ensuring that OpenShift Container Platform works properly
under future versions of docker. (BZ#1358197)

* The PersistentVolumeLabel admission plug-in is now enabled by
default. This plug-in labels AWS and GCE volumes with their zone so
the scheduler can limit the nodes for a pod to only those in the same
zone as the persistent volumes being used by the pod. (BZ#1365600)

* Previously, heapster incorrectly generated error messages indicating
that it 'Failed to find node'. This bug fix corrects that error and
ensures that erroneous warnings are generated.(BZ#1366367)

* The deployment controllers' resync interval can now be configured.
The previously hard-coded 2-minute default is the likely cause of
performance regressions when thousands of deploymentconfigs are
present in the system. Increase the resync interval by setting
deploymentControllerResyncMinute in
/etc/origin/master/master-config.yaml.(BZ#1366381)

* Previously, AWS-related environment variables were removed from
/etc/ sysconfig/atomic-openshift-master files during an upgrade if
these values were not included in the advanced installer's inventory
file. This bug fix ensures that these variables are now preserved
during upgrades. (BZ# 1370641)

* Previously, updates to the containerized atomic-openshift-node
service were not properly reloaded during upgrades. This bug fix
corrects this error and ensures that the service is reloaded during
upgrades. (BZ#1371708)

* Previously the installer did not properly configure an environment
for flannel when openshift_use_flannel was set to `true`. This bug fix
corrects those errors and the installer will now correctly deploy
environments using flannel. (BZ#1372026)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:1853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-5418"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-dockerregistry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-pod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-recycle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-sdn-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:heapster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-filter-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-lookup-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-playbooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-roles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tuned-profiles-atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/12");
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
  rhsa = "RHSA-2016:1853";
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
  if (rpm_exists(rpm:"atomic-openshift-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-3.2.1.15-1.git.0.d84be7f.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-3.2.1.15-1.git.0.d84be7f.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-redistributable-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-redistributable-3.2.1.15-1.git.0.d84be7f.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-dockerregistry-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-dockerregistry-3.2.1.15-1.git.0.d84be7f.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-master-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-master-3.2.1.15-1.git.0.d84be7f.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-node-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-node-3.2.1.15-1.git.0.d84be7f.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-pod-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-pod-3.2.1.15-1.git.0.d84be7f.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-recycle-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-recycle-3.2.1.15-1.git.0.d84be7f.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-sdn-ovs-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-sdn-ovs-3.2.1.15-1.git.0.d84be7f.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-tests-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-tests-3.2.1.15-1.git.0.d84be7f.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-utils-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-utils-3.2.28-1.git.0.5a85fc5.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"heapster-1.1.0-1.beta2.el7.1")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-3.2.28-1.git.0.5a85fc5.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-docs-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-docs-3.2.28-1.git.0.5a85fc5.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-filter-plugins-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-filter-plugins-3.2.28-1.git.0.5a85fc5.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-lookup-plugins-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-lookup-plugins-3.2.28-1.git.0.5a85fc5.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-playbooks-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-playbooks-3.2.28-1.git.0.5a85fc5.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-roles-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-roles-3.2.28-1.git.0.5a85fc5.el7")) flag++;
  if (rpm_exists(rpm:"tuned-profiles-atomic-openshift-node-3.2", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tuned-profiles-atomic-openshift-node-3.2.1.15-1.git.0.d84be7f.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "atomic-openshift / atomic-openshift-clients / etc");
  }
}
