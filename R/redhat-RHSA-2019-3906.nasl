#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3906. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131154);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-9512", "CVE-2019-9514");
  script_xref(name:"RHSA", value:"2019:3906");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"RHEL 7 : OpenShift Container Platform 3.11 HTTP/2 (RHSA-2019:3906) (Ping Flood) (Reset Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update is now available for Red Hat OpenShift Container Platform
3.11.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat OpenShift Container Platform is Red Hat's cloud computing
Kubernetes application platform solution designed for on-premise or
private cloud deployments.

The following RPM packages have been rebuilt with updated version of
Go, which includes the security fixes listed further below :

atomic-enterprise-service-catalog atomic-openshift-cluster-autoscaler
atomic-openshift-descheduler atomic-openshift-metrics-server
atomic-openshift-node-problem-detector atomic-openshift-service-idler
atomic-openshift-web-console cockpit csi-attacher csi-driver-registrar
csi-livenessprobe csi-provisioner golang-github-openshift-oauth-proxy
golang-github-openshift-prometheus-alert-buffer
golang-github-prometheus-alertmanager
golang-github-prometheus-node_exporter
golang-github-prometheus-prometheus hawkular-openshift-agent heapster
image-inspector openshift-enterprise-autoheal
openshift-enterprise-cluster-capacity openshift-eventrouter
openshift-external-storage

Security Fix(es) :

* HTTP/2: flood using PING frames results in unbounded memory growth
(CVE-2019-9512)

* HTTP/2: flood using HEADERS frames results in unbounded memory
growth (CVE-2019-9514)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3906");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-enterprise-service-catalog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-enterprise-service-catalog-svcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-cluster-autoscaler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-descheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-metrics-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node-problem-detector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-service-idler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-web-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cockpit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cockpit-kubernetes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-attacher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-attacher-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-driver-registrar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-driver-registrar-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-livenessprobe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-livenessprobe-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:csi-provisioner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-openshift-oauth-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:golang-github-openshift-prometheus-alert-buffer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hawkular-openshift-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:heapster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:image-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-autoheal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-cluster-capacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-eventrouter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-eventrouter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-cephfs-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-efs-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-local-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-manila-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-snapshot-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-snapshot-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prometheus-alertmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prometheus-node-exporter");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3906";
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
  if (rpm_exists(rpm:"atomic-enterprise-service-catalog-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-enterprise-service-catalog-3.11.154-1.git.1.fa68ced.el7")) flag++;
  if (rpm_exists(rpm:"atomic-enterprise-service-catalog-svcat-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-enterprise-service-catalog-svcat-3.11.154-1.git.1.fa68ced.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-cluster-autoscaler-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-cluster-autoscaler-3.11.154-1.git.1.532da7a.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-descheduler-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-descheduler-3.11.154-1.git.1.1d31032.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-metrics-server-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-metrics-server-3.11.154-1.git.1.6a6b6ce.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-node-problem-detector-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-node-problem-detector-3.11.154-1.git.1.5e8e065.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-service-idler-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-service-idler-3.11.154-1.git.1.f80fb86.el7")) flag++;
  if (rpm_exists(rpm:"atomic-openshift-web-console-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"atomic-openshift-web-console-3.11.154-1.git.1.f54cb18.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cockpit-debuginfo-195-2.rhaos.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cockpit-kubernetes-195-2.rhaos.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"csi-attacher-0.2.0-4.git27299be.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"csi-attacher-debuginfo-0.2.0-4.git27299be.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"csi-driver-registrar-0.2.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"csi-driver-registrar-debuginfo-0.2.0-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"csi-livenessprobe-0.0.1-2.gitff5b6a0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"csi-livenessprobe-debuginfo-0.0.1-2.gitff5b6a0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"csi-provisioner-0.2.0-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"csi-provisioner-debuginfo-0.2.0-3.el7")) flag++;
  if (rpm_exists(rpm:"golang-github-openshift-oauth-proxy-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"golang-github-openshift-oauth-proxy-3.11.154-1.git.1.220e3dc.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"golang-github-openshift-prometheus-alert-buffer-0-3.gitceca8c1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"hawkular-openshift-agent-1.2.2-3.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"heapster-1.3.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"image-inspector-2.4.0-4.el7")) flag++;
  if (rpm_exists(rpm:"openshift-enterprise-autoheal-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-enterprise-autoheal-3.11.154-1.git.1.13199be.el7")) flag++;
  if (rpm_exists(rpm:"openshift-enterprise-cluster-capacity-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-enterprise-cluster-capacity-3.11.154-1.git.1.5798c2c.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-eventrouter-0.2-4.git7c289cc.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-eventrouter-debuginfo-0.2-4.git7c289cc.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-cephfs-provisioner-0.0.2-9.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-debuginfo-0.0.2-9.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-efs-provisioner-0.0.2-9.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-local-provisioner-0.0.2-9.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-manila-provisioner-0.0.2-9.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-snapshot-controller-0.0.2-9.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-snapshot-provisioner-0.0.2-9.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"prometheus-3.11.154-1.git.1.148db48.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"prometheus-alertmanager-3.11.154-1.git.1.4acd2e6.el7")) flag++;
  if (rpm_exists(rpm:"prometheus-node-exporter-3.11", release:"RHEL7") && rpm_check(release:"RHEL7", cpu:"x86_64", reference:"prometheus-node-exporter-3.11.154-1.git.1.bc9f224.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "atomic-enterprise-service-catalog / etc");
  }
}
