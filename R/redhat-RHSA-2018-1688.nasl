#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1688. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110079);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2018-3639");
  script_xref(name:"RHSA", value:"2018:1688");
  script_xref(name:"IAVA", value:"2018-A-0170");

  script_name(english:"RHEL 6 : Virtualization (RHSA-2018:1688) (Spectre)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for org.ovirt.engine-root is now available for RHEV Manager
version 3.6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The org.ovirt.engine-root is a core component of oVirt.

Security Fix(es) :

* An industry-wide issue was found in the way many modern
microprocessor designs have implemented speculative execution of Load
& Store instructions (a commonly used performance optimization). It
relies on the presence of a precisely-defined instruction sequence in
the privileged code as well as the fact that memory read from address
to which a recent memory write has occurred may see an older value and
subsequently cause an update into the microprocessor's data cache even
for speculatively executed instructions that never actually commit
(retire). As a result, an unprivileged attacker could use this flaw to
read privileged memory by conducting targeted cache side-channel
attacks. (CVE-2018-3639)

Note: This is the org.ovirt.engine-root side of the CVE-2018-3639
mitigation.

Red Hat would like to thank Ken Johnson (Microsoft Security Response
Center) and Jann Horn (Google Project Zero) for reporting this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/vulnerabilities/ssbd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-3639"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-extensions-api-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-extensions-api-impl-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-ovirt-engine-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup-plugin-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-tools-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-userportal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-userportal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-webadmin-portal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/24");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:1688";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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

  if (! (rpm_exists(release:"RHEL6", rpm:"rhevm-3.6"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Virtualization");

  if (rpm_exists(rpm:"rhevm-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-backend-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-backend-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-dbscripts-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-dbscripts-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-extensions-api-impl-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-extensions-api-impl-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-extensions-api-impl-javadoc-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-extensions-api-impl-javadoc-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-lib-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-lib-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-restapi-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-restapi-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-base-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-base-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-ovirt-engine-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-ovirt-engine-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-ovirt-engine-common-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-ovirt-engine-common-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-vmconsole-proxy-helper-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-vmconsole-proxy-helper-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-plugin-websocket-proxy-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-setup-plugin-websocket-proxy-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-tools-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-tools-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-tools-backup-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-tools-backup-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-userportal-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-userportal-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-userportal-debuginfo-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-userportal-debuginfo-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-vmconsole-proxy-helper-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-vmconsole-proxy-helper-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-webadmin-portal-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-webadmin-portal-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-webadmin-portal-debuginfo-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-webadmin-portal-debuginfo-3.6.13.2-0.1.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-websocket-proxy-3.6.", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"rhevm-websocket-proxy-3.6.13.2-0.1.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhevm / rhevm-backend / rhevm-dbscripts / rhevm-extensions-api-impl / etc");
  }
}
