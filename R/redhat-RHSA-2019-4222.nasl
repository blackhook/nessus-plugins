#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:4222. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132031);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/20");

  script_cve_id("CVE-2019-18801", "CVE-2019-18802", "CVE-2019-18838");
  script_xref(name:"RHSA", value:"2019:4222");

  script_name(english:"RHEL 8 : Red Hat OpenShift Service Mesh 1.0.3 RPMs (RHSA-2019:4222)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat OpenShift Service Mesh 1.0.3.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat OpenShift Service Mesh is Red Hat's distribution of the Istio
service mesh project, tailored for installation into an on-premise
OpenShift Container Platform installation.

This advisory covers the RPM packages for the OpenShift Service Mesh
1.0.3 release.

Security Fix(es) :

* An untrusted remote client may send HTTP/2 requests that write to
the heap outside of the request buffers when the upstream is HTTP/1
(CVE-2019-18801)

* Malformed request header may cause bypass of route matchers
resulting in escalation of privileges or information disclosure
(CVE-2019-18802)

* Malformed HTTP request without the Host header may cause abnormal
termination of the Envoy process (CVE-2019-18838)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:4222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-18801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-18802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-18838"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18802");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-citadel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-cni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-galley");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-grafana-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-istioctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-mixc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-mixs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-operator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-pilot-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-pilot-discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:servicemesh-sidecar-injector");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(7|8)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x / 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:4222";
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
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-1.0.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-citadel-1.0.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-cni-1.0.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-galley-1.0.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-grafana-6.2.2-25.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-grafana-prometheus-6.2.2-25.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-istioctl-1.0.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-mixc-1.0.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-mixs-1.0.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-operator-1.0.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-pilot-agent-1.0.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-pilot-discovery-1.0.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-prometheus-2.7.2-26.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-proxy-1.0.3-1.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"servicemesh-sidecar-injector-1.0.3-1.el8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "servicemesh / servicemesh-citadel / servicemesh-cni / etc");
  }
}
