#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0615. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119369);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/11");

  script_cve_id("CVE-2016-2074");
  script_xref(name:"RHSA", value:"2016:0615");

  script_name(english:"RHEL 7 : openvswitch (RHSA-2016:0615)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated openvswitch packages that fix one security issue are now
available for Red Hat OpenShift Enterprise 3.1.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

OpenShift Enterprise by Red Hat is the company's cloud computing
Platform-as-a-Service (PaaS) solution designed for on-premise or
private cloud deployments.

A buffer overflow flaw was discovered in the OVS processing of MPLS
labels. A remote attacker able to deliver a frame containing a
malicious MPLS label that would be processed by OVS could trigger the
flaw and use the resulting memory corruption to cause a denial of
service (DoS) or, possibly, execute arbitrary code. (CVE-2016-2074)

Red Hat would like to thank the Open vSwitch Project for reporting
these issues. Upstream acknowledges Kashyap Thimmaraju and Bhargava
Shastry as the original reporters of CVE-2016-2074.

This update includes the following images :

openshift3/openvswitch:v3.1.1.6-9 aep3_beta/openvswitch:v3.1.1.6-9
openshift3/node:v3.1.1.6-16 aep3_beta/node:v3.1.1.6-16

All openvswitch users are advised to upgrade to this updated package,
which contains a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:0615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-2074"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/11");
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
  rhsa = "RHSA-2016:0615";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-2.4.0-2.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-debuginfo-2.4.0-2.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openvswitch-devel-2.4.0-2.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", reference:"openvswitch-test-2.4.0-2.el7_2")) flag++;
  if (rpm_check(release:"RHEL7", reference:"python-openvswitch-2.4.0-2.el7_2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvswitch / openvswitch-debuginfo / openvswitch-devel / etc");
  }
}
