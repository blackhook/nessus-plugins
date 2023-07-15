#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3131. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129995);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-9512", "CVE-2019-9514");
  script_xref(name:"RHSA", value:"2019:3131");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"RHEL 7 / 8 : OpenShift Container Platform 4.1.20 golang (RHSA-2019:3131) (Ping Flood) (Reset Flood)");

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

This advisory contains the cri-o, cri-tools, faq, ignition,
openshift-external-storage and pivot RPM packages, which have been
rebuilt with an updated version of golang for Red Hat OpenShift
Container Platform 4.1.20.

Security Fix(es) :

* HTTP/2: flood using PING frames results in unbounded memory growth
(CVE-2019-9512)

* HTTP/2: flood using HEADERS frames results in unbounded memory
growth (CVE-2019-9514)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3131");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:faq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:faq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ignition-validate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-cephfs-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-efs-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-local-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-manila-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-snapshot-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-external-storage-snapshot-provisioner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pivot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
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
if (! preg(pattern:"^(7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x / 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3131";
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

  if (! (rpm_exists(release:"RHEL7", rpm:"atomic-openshift-") || rpm_exists(release:"RHEL8", rpm:"atomic-openshift-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenShift");

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cri-o-1.13.11-0.10.dev.rhaos4.1.gitbdeb2ca.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cri-o-debuginfo-1.13.11-0.10.dev.rhaos4.1.gitbdeb2ca.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cri-tools-1.13.0-2.rhaos4.1.gitc06001f.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"cri-tools-debuginfo-1.13.0-2.rhaos4.1.gitc06001f.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"faq-0.0.6-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"faq-debuginfo-0.0.6-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-cephfs-provisioner-0.0.2-7.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-debuginfo-0.0.2-7.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-efs-provisioner-0.0.2-7.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-local-provisioner-0.0.2-7.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-manila-provisioner-0.0.2-7.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-snapshot-controller-0.0.2-7.gitd3c94f0.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openshift-external-storage-snapshot-provisioner-0.0.2-7.gitd3c94f0.el7")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"cri-o-1.13.11-0.13.dev.rhaos4.1.gitbdeb2ca.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"cri-tools-1.13.0-3.rhaos4.1.gitb69a0b9.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ignition-0.32.0-2.git5941fc0.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"ignition-validate-0.32.0-2.git5941fc0.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pivot-0.0.5-2.el8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cri-o / cri-o-debuginfo / cri-tools / cri-tools-debuginfo / faq / etc");
  }
}
