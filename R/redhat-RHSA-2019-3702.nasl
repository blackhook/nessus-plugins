#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:3702. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130569);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2018-20685", "CVE-2019-6109", "CVE-2019-6111");
  script_xref(name:"RHSA", value:"2019:3702");

  script_name(english:"RHEL 8 : openssh (RHSA-2019:3702)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for openssh is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

OpenSSH is an SSH protocol implementation supported by a number of
Linux, UNIX, and similar operating systems. It includes the core files
necessary for both the OpenSSH client and server.

The following packages have been upgraded to a later upstream version:
openssh (8.0p1). (BZ#1691045)

Security Fix(es) :

* openssh: scp client improper directory name validation
(CVE-2018-20685)

* openssh: Improper validation of object names allows malicious server
to overwrite files via scp client (CVE-2019-6111)

* openssh: Missing character encoding in progress display allows for
spoofing of scp client output (CVE-2019-6109)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 8.1 Release Notes linked from the References section.");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?774148ae");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3702");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2018-20685");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-6109");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2019-6111");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6111");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-6109");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-askpass-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-clients-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-keycat-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pam_ssh_agent_auth-debuginfo");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:3702";
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
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-askpass-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-askpass-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-askpass-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-askpass-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-cavs-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-cavs-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-cavs-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-cavs-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-clients-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-clients-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-clients-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-clients-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-debugsource-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-debugsource-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-keycat-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-keycat-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-keycat-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-keycat-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-ldap-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-ldap-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-ldap-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-ldap-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-server-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-server-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openssh-server-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openssh-server-debuginfo-8.0p1-3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"pam_ssh_agent_auth-0.10.3-7.3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pam_ssh_agent_auth-0.10.3-7.3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"pam_ssh_agent_auth-debuginfo-0.10.3-7.3.el8")) flag++;
  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"pam_ssh_agent_auth-debuginfo-0.10.3-7.3.el8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-askpass-debuginfo / etc");
  }
}
