#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:0972. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124665);
  script_version("1.6");
  script_cvs_date("Date: 2020/01/30");

  script_cve_id("CVE-2019-3816");
  script_xref(name:"RHSA", value:"2019:0972");

  script_name(english:"RHEL 8 : openwsman (RHSA-2019:0972)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for openwsman is now available for Red Hat Enterprise Linux
8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Openwsman is a project intended to provide an open source
implementation of the Web Services Management specification
(WS-Management) and to expose system management information on the
Linux operating system using the WS-Management protocol. WS-Management
is based on a suite of web services specifications and usage
requirements that cover all system management aspects.

Security Fix(es) :

* openwsman: Disclosure of arbitrary files outside of the registered
URIs (CVE-2019-3816)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:0972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-3816"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwsman-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwsman1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwsman1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openwsman-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openwsman-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openwsman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openwsman-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openwsman-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openwsman-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openwsman-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openwsman-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openwsman-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openwsman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:0972";
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
  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"libwsman-devel-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"i686", reference:"libwsman-devel-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"s390x", reference:"libwsman-devel-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"x86_64", reference:"libwsman-devel-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libwsman1-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libwsman1-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libwsman1-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"libwsman1-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"libwsman1-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"libwsman1-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"libwsman1-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"openwsman-client-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openwsman-client-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openwsman-client-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"openwsman-client-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"openwsman-client-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openwsman-client-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openwsman-client-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"openwsman-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"openwsman-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openwsman-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openwsman-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"openwsman-debugsource-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"openwsman-debugsource-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openwsman-debugsource-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openwsman-debugsource-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"openwsman-perl-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"openwsman-perl-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openwsman-perl-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openwsman-perl-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openwsman-python3-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openwsman-python3-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"openwsman-python3-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"openwsman-python3-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openwsman-python3-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openwsman-python3-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"openwsman-server-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openwsman-server-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openwsman-server-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"openwsman-server-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"openwsman-server-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"openwsman-server-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"openwsman-server-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", sp:"0", cpu:"aarch64", reference:"rubygem-openwsman-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"rubygem-openwsman-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"rubygem-openwsman-debuginfo-2.6.5-5.el8")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"rubygem-openwsman-debuginfo-2.6.5-5.el8")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwsman-devel / libwsman1 / libwsman1-debuginfo / openwsman-client / etc");
  }
}