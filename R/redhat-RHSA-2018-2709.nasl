#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2709. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119405);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id("CVE-2018-14632", "CVE-2018-14645");
  script_xref(name:"RHSA", value:"2018:2709");

  script_name(english:"RHEL 7 : Red Hat OpenShift Container Platform 3.10 (RHSA-2018:2709)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Red Hat OpenShift Container Platform release 3.10.66 is now available
with updates to packages and images that fix several security, bug,
and add enhancements.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat OpenShift Container Platform is Red Hat's cloud computing
Kubernetes application platform solution designed for on-premise or
private cloud deployments.

This advisory contains the RPM packages for Red Hat OpenShift
Container Platform 3.10.66. See the following advisory for the
container images for this release :

https://access.redhat.com/errata/RHBA-2018:2824

Security Fix(es) :

* atomic-openshift: oc patch with json causes masterapi service crash
(CVE-2018-14632)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Red Hat would like to thank Lars Haugan for reporting this issue.

All OpenShift Container Platform 3.10 users are advised to upgrade to
these updated packages and images.

Bug Fix(es) :

* During etcd scaleup, facts about the etcd cluster are required to
add new hosts. This bug fix adds the necessary tasks to ensure those
facts get set before configuring new hosts, and therefore, allow the
scaleup to complete as expected. (BZ#1578482)

* Previously, sync pod was not available when the Prometheus install
checked for available nodes. As a consequence, if a custom label was
used for the Prometheus install to select an appropriate node, the
sync pods must have already applied the label to the nodes. Otherwise,
the Prometheus installer would not find any nodes with a matching
label. This bug fix adds a check to the install process to wait for
sync pods to become available before continuing. As a result, the node
labeling process will complete, and the nodes will have the correct
labels for the Prometheus pod to be scheduled. (BZ#1609019)

* This bug fix corrects an issue where a pod is stuck terminating due
to I/O errors on a FlexVolume mounted on the XFS file system.
(BZ#1626054)

* Previously, fluentd generated events internally with the
`OneEventStream` class. This class does not have the `empty?` method.
The Kubernetes metadata filter used the `empty?` method on the
`EventStream` object to avoid processing an empty stream. Fluentd
issued error messages about the missing `empty?` method, which
overwhelmed container logging and caused disk issues. This bug fix
changed the Kubernetes metadata filter only to call the `empty?`
method on objects that have this method. As a result, fluentd logs do
not contain this message. (BZ#1626552)

* RubyGems FFI 1.9.25 reverted a patch which allowed it to work on
systems with `SELinux deny_execmem=1`. This reversion caused fluentd
to crash. This bug reverts the patch reversion. As a result, fluentd
does not crash when using `SELinux deny_execmem=1`. (BZ#1628405)

* This bug fix updates the *_redeploy-openshift-ca.yml_* playbook to
reference the correct node client certificate file,
`node/client-ca.crt`. (BZ#1628546)

* The fix for BZ1628371 introduced a poorly built shared library with
a missing symbol. This missing symbol caused fluentd to crash with an
'undefined symbol: rbffi_Closure_Alloc' error message. This bug fix
rebuilds the shared library with the correct symbols. As a result,
fluentd does not crash. (BZ#1628798)

* Previously, when using Docker with the journald log driver, all
container logs, including system and plain Docker container logs, were
logged to the journal, and read by fluentd. Fluentd did not know how
to handle these non-Kubernetes container logs and threw exceptions.
This bug fix treats non-Kubernetes container logs as logs from other
system services, for example, sending them to the .operations.* index.
As a result, logs from non-Kubernetes containers are indexed correctly
and do not cause any errors. (BZ#1632361)");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:2709");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14632");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-14645");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14645");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-14632");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-enterprise-service-catalog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-enterprise-service-catalog-svcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-descheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-docker-excluder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-dockerregistry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-excluder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-hyperkube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-hypershift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node-problem-detector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-pod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-sdn-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-template-service-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-web-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:image-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-playbooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-ansible-roles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-cluster-capacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-monitor-project-lifecycle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-IO-String");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prometheus-node-exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ffi-debuginfo");
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
  rhsa = "RHSA-2018:2709";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"atomic-openshift-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenShift");

  if (rpm_exists(rpm:"atomic-enterprise-service-catalog-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-enterprise-service-catalog-3.10.66-1.git.1450.b758bdb.el7")) flag++;
  if (rpm_exists(rpm:"atomic-enterprise-service-catalog-svcat-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-enterprise-service-catalog-svcat-3.10.66-1.git.1450.b758bdb.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-redistributable-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-redistributable-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-descheduler-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-descheduler-3.10.66-1.git.299.e466391.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-docker-excluder-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-docker-excluder-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-dockerregistry-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-dockerregistry-3.10.66-1.git.390.77310f8.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-excluder-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-excluder-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-hyperkube-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-hyperkube-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-hypershift-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-hypershift-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-master-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-master-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-node-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-node-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-node-problem-detector-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-node-problem-detector-3.10.66-1.git.198.2fcf818.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-pod-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-pod-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-sdn-ovs-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-sdn-ovs-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-template-service-broker-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-template-service-broker-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-tests-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-tests-3.10.66-1.git.0.91d1e89.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-web-console-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-web-console-3.10.66-1.git.389.adbeb58.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"haproxy-debuginfo-1.8.14-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"haproxy18-1.8.14-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"image-inspector-2.4.0-3.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-3.10.66-1.git.0.3c3a83a.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-docs-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-docs-3.10.66-1.git.0.3c3a83a.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-playbooks-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-playbooks-3.10.66-1.git.0.3c3a83a.el7")) flag++;
  if (rpm_exists(rpm:"openshift-ansible-roles-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"openshift-ansible-roles-3.10.66-1.git.0.3c3a83a.el7")) flag++;
  if (rpm_exists(rpm:"openshift-enterprise-cluster-capacity-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-enterprise-cluster-capacity-3.10.66-1.git.380.aef3728.el7")) flag++;
  if (rpm_exists(rpm:"openshift-monitor-project-lifecycle-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-monitor-project-lifecycle-3.10.66-1.git.59.57c03d5.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"perl-IO-String-1.08-20.el7")) flag++;
  if (rpm_exists(rpm:"prometheus-node-exporter-3.10", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"prometheus-node-exporter-3.10.66-1.git.1060.f6046fd.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-py-1.4.32-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-setuptools-17.1.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-ffi-1.9.25-4.el7_5")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-ffi-debuginfo-1.9.25-4.el7_5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "atomic-enterprise-service-catalog / etc");
  }
}
