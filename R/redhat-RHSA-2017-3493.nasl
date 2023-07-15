#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3493. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105479);
  script_version("3.6");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_xref(name:"RHSA", value:"2017:3493");

  script_name(english:"RHEL 6 : MRG (RHSA-2017:3493)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the 6-month notification for the retirement of Red Hat
Enterprise MRG Version 2 for Red Hat Enterprise Linux 6.

This notification applies only to those customers subscribed to Red
Hat Enterprise MRG Version 2 for Red Hat Enterprise Linux 6.

In accordance with the Red Hat Enterprise MRG Life Cycle policy, Red
Hat Enterprise MRG Version 2 for Red Hat Enterprise Linux 6 will be
retired as of June 30, 2018, and active support will no longer be
provided.

Accordingly, Red Hat will no longer provide updated packages,
including Critical Impact security patches or Urgent Priority bug
fixes, for Red Hat Enterprise MRG Version 2 for Red Hat Enterprise
Linux 6 after June 30, 2018. In addition, on-going technical support
through Red Hat's Customer Experience and Engagement will be limited
as described under 'non-current minor releases' in the Knowledge Base
article located here https://access.redhat.com/articles/ 3234591 after
this date.

Red Hat Enterprise MRG-Realtime customers are advised to migrate to
Red Hat Enterprise Linux for Real Time 7 at this time. Red Hat
Enterprise Linux for Real Time 7 is available with most Red Hat
Enterprise MRG-Realtime subscriptions to allow customers to plan their
migration. Red Hat Enterprise Linux for Real Time 7 is the most
current version of our real time offering and is actively supported
today.

Details of the Red Hat Enterprise MRG life cycle can be found here:
https:// access.redhat.com/support/policy/updates/mrg

Additional information on Red Hat Enterprise Linux for Real Time can
be found here (see 'Red Hat Enterprise Linux Portfolio'):
https://access.redhat.com/ products/red-hat-enterprise-linux/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/3234591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/support/policy/updates/mrg/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/products/red-hat-enterprise-linux/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:3493"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mrg-release package."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mrg-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2017:3493";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL6", reference:"mrg-release-2.5.0-2.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mrg-release");
  }
}
