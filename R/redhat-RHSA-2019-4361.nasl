#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:4361. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(132393);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2019-18397");
  script_xref(name:"RHSA", value:"2019:4361");

  script_name(english:"RHEL 8 : fribidi (RHSA-2019:4361)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for fribidi is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

A library to handle bidirectional scripts (for example Hebrew,
Arabic), so that the display is done in the proper way, while the text
data itself is always written in logical order.

Security Fix(es) :

* fribidi: buffer overflow in fribidi_get_par_embedding_levels_ex() in
lib/ fribidi-bidi.c leading to denial of service and possible code
execution (CVE-2019-18397)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:4361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-18397"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fribidi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fribidi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fribidi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fribidi-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/24");
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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 8.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:4361";
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
  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"fribidi-1.0.4-7.el8_1")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"fribidi-1.0.4-7.el8_1")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"fribidi-1.0.4-7.el8_1")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"fribidi-debuginfo-1.0.4-7.el8_1")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"fribidi-debuginfo-1.0.4-7.el8_1")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"fribidi-debuginfo-1.0.4-7.el8_1")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"fribidi-debugsource-1.0.4-7.el8_1")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"fribidi-debugsource-1.0.4-7.el8_1")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"fribidi-debugsource-1.0.4-7.el8_1")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"i686", reference:"fribidi-devel-1.0.4-7.el8_1")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"s390x", reference:"fribidi-devel-1.0.4-7.el8_1")) flag++;

  if (rpm_check(release:"RHEL8", cpu:"x86_64", reference:"fribidi-devel-1.0.4-7.el8_1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fribidi / fribidi-debuginfo / fribidi-debugsource / fribidi-devel");
  }
}
