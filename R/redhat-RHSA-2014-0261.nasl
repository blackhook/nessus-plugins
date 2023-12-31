#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0261. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76673);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_xref(name:"RHSA", value:"2014:0261");

  script_name(english:"RHEL 5 : MRG (RHSA-2014:0261)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the one-month notification for the retirement of Red Hat
Enterprise MRG Version 1 for Red Hat Enterprise Linux 5. This
notification applies only to those customers with subscriptions for
Red Hat Enterprise MRG Version 1 for Red Hat Enterprise Linux 5.

In accordance with the Red Hat Enterprise MRG Life Cycle policy, the
Red Hat Enterprise MRG product, which includes MRG-Messaging,
MRG-Realtime, and MRG-Grid, Version 1 offering for Red Hat Enterprise
Linux 5 will be retired as of March 31, 2014, and support will no
longer be provided.

Accordingly, Red Hat will no longer provide updated packages,
including critical impact security patches or urgent priority bug
fixes, for MRG-Messaging, MRG-Realtime, and MRG-Grid Version 1 on Red
Hat Enterprise Linux 5 after that date. In addition, technical support
through Red Hat's Global Support Services will no longer be provided
for Red Hat Enterprise MRG Version 1 on Red Hat Enterprise Linux 5
after March 31, 2014.

We encourage customers to plan their migration from Red Hat Enterprise
MRG Version 1 for Red Hat Enterprise Linux 5 to Red Hat Enterprise MRG
Version 2 on either Red Hat Enterprise Linux 5 or Red Hat Enterprise
Linux 6. As a benefit of the Red Hat subscription model, customers can
use their active Red Hat Enterprise MRG subscriptions to entitle any
system on a currently supported version of those products.

Details of the Red Hat Enterprise MRG life cycle can be found here:
https://access.redhat.com/site/support/policy/updates/mrg/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/site/support/policy/updates/mrg/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:0261"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mrg-release package."
  );
  script_set_attribute(attribute:"risk_factor", value:"Low");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mrg-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0261";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"mrg-release"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "MRG");

  if (rpm_check(release:"RHEL5", reference:"mrg-release-2.4.0-5.el5_10")) flag++;

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
