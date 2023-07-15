#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1883. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110604);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/10");

  script_cve_id("CVE-2018-1050");
  script_xref(name:"RHSA", value:"2018:1883");

  script_name(english:"RHEL 6 : samba4 (RHSA-2018:1883)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for samba4 is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

Security Fix(es) :

* samba: NULL pointer indirection in printer server process
(CVE-2018-1050)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank the Samba project for reporting this
issue.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.10 Release Notes and Red Hat Enterprise Linux 6.10
Technical Notes linked from the References section."
  );
  # https://access.redhat.com/documentation/en-US/red_hat_enterprise_linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d2572ef"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1050"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-dc-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/19");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:1883";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-client-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-client-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-client-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-common-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-common-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-common-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-dc-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-dc-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-dc-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-dc-libs-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-dc-libs-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-dc-libs-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-debuginfo-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-debuginfo-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-debuginfo-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-devel-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-devel-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-devel-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-libs-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-libs-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-libs-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-pidl-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-pidl-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-pidl-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-python-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-python-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-python-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-test-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-test-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-test-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-clients-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-clients-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-clients-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"samba4-winbind-krb5-locator-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"samba4-winbind-krb5-locator-4.2.10-15.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"samba4-winbind-krb5-locator-4.2.10-15.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba4 / samba4-client / samba4-common / samba4-dc / samba4-dc-libs / etc");
  }
}
