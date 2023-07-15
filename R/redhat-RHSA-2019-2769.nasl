#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2769. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130185);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-11247", "CVE-2019-9512", "CVE-2019-9514");
  script_xref(name:"RHSA", value:"2019:2769");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"RHEL 7 : OpenShift Container Platform 3.9 (RHSA-2019:2769) (Ping Flood) (Reset Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An security update is now available for Red Hat OpenShift Container
Platform 3.9.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat OpenShift Container Platform is Red Hat's cloud computing
Kubernetes application platform solution designed for on-premise or
private cloud deployments.

This advisory contains RPM packages for Red Hat OpenShift Container
Platform 3.9, which have been rebuilt with an updated version of
golang.

Security Fix(es) :

* HTTP/2: flood using PING frames results in unbounded memory growth
(CVE-2019-9512)

* HTTP/2: flood using HEADERS frames results in unbounded memory
growth (CVE-2019-9514)

* kubernetes: API server allows access to cluster-scoped custom
resources as if resources were namespaced (CVE-2019-11247)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:2769");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9512");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-9514");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-11247");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11247");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-service-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-service-broker-container-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-service-broker-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-cluster-capacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-descheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-docker-excluder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-dockerregistry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-excluder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-federation-services");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node-problem-detector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-pod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-sdn-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-service-catalog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-template-service-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-web-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cockpit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cockpit-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-openshift-oauth-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-openshift-prometheus-alert-buffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-prometheus-promu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hawkular-openshift-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:heapster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:image-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-image-registry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-eventrouter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-eventrouter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-efs-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-local-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-snapshot-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-snapshot-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-ovn-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prometheus-alertmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prometheus-node-exporter");
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
  rhsa = "RHSA-2019:2769";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ansible-service-broker-1.1.20-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ansible-service-broker-container-scripts-1.1.20-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ansible-service-broker-selinux-1.1.20-2.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-clients-redistributable-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-clients-redistributable-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-cluster-capacity-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-cluster-capacity-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-descheduler-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-descheduler-3.9.13-2.git.267.bb59a3f.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-docker-excluder-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-docker-excluder-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-dockerregistry-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-dockerregistry-3.9.101-1.git.1.13625cf.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-excluder-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", reference:"atomic-openshift-excluder-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-federation-services-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-federation-services-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-master-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-master-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-node-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-node-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-node-problem-detector-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-node-problem-detector-3.9.13-2.git.167.5d6b0d4.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-pod-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-pod-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-sdn-ovs-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-sdn-ovs-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-service-catalog-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-service-catalog-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-template-service-broker-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-template-service-broker-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-tests-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-tests-3.9.101-1.git.0.150f595.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-web-console-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-web-console-3.9.101-1.git.1.601c6d2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cockpit-debuginfo-195-2.rhaos.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cockpit-kubernetes-195-2.rhaos.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"containernetworking-plugins-0.5.2-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"containernetworking-plugins-debuginfo-0.5.2-6.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cri-o-1.9.16-3.git858756d.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cri-o-debuginfo-1.9.16-3.git858756d.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cri-tools-1.0.0-6.rhaos3.9.git8e6013a.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cri-tools-debuginfo-1.0.0-6.rhaos3.9.git8e6013a.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"golang-github-openshift-oauth-proxy-2.1-3.git885c9f40.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"golang-github-openshift-prometheus-alert-buffer-0-3.gitceca8c1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"golang-github-prometheus-promu-0-5.git85ceabc.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"hawkular-openshift-agent-1.2.2-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"heapster-1.3.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"image-inspector-2.1.3-2.el7")) flag++;
  if (rpm_exists(rpm:"openshift-enterprise-image-registry-3.8", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-enterprise-image-registry-3.8.0-2.git.216.b6b90bb.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-eventrouter-0.1-3.git5bd9251.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-eventrouter-debuginfo-0.1-3.git5bd9251.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-debuginfo-0.0.1-9.git78d6339.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-efs-provisioner-0.0.1-9.git78d6339.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-local-provisioner-0.0.1-9.git78d6339.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-snapshot-controller-0.0.1-9.git78d6339.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-snapshot-provisioner-0.0.1-9.git78d6339.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-ovn-kubernetes-0.1.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"prometheus-2.2.1-2.gitbc6058c.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"prometheus-alertmanager-0.14.0-2.git30af4d0.el7")) flag++;
  if (rpm_exists(rpm:"prometheus-node-exporter-3.9", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"prometheus-node-exporter-3.9.101-1.git.1.8295224.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"prometheus-promu-0-5.git85ceabc.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ansible-service-broker / ansible-service-broker-container-scripts / etc");
  }
}
