#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0578. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64943);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_xref(name:"RHSA", value:"2013:0578");

  script_xref(name:"IAVA", value:"0001-A-0644");

  script_name(english:"RHEL 5 : redhat-release (EOL Notice) (RHSA-2013:0578)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the 5-Month notification for the conclusion of Red Hat
Enterprise Linux 5.6 Extended Update Support (EUS) Add-on offering.

In accordance with the Red Hat Enterprise Linux Errata Support Policy,
the Extended Update Support Add-On for Red Hat Enterprise Linux 5.6
will conclude on July 31, 2013. Accordingly, Red Hat will no longer
provide updated packages, including critical impact security patches
or urgent priority bug fixes, for Red Hat Enterprise Linux 5.6 EUS
after that date. In addition, after July 31, 2013, technical support
through Red Hat's Global Support Services will no longer be provided
for this Add-on.

Note: This notification applies only to those customers subscribed to
the Extended Update Support (EUS) channel for Red Hat Enterprise Linux
5.6.

We encourage customers to plan their migration from Red Hat Enterprise
Linux 5.6 to a more recent version of Red Hat Enterprise Linux 5 or 6.
As a benefit of the Red Hat subscription model, customers can use
their active subscriptions to entitle any system on a currently
supported Red Hat Enterprise Linux 5 release (5.9, for which EUS is
available) or Red Hat Enterprise Linux 6 release (6.2, 6.3, or 6.4,
for which EUS is available).

Details of the Red Hat Enterprise Linux life cycle can be found here:
https://www.redhat.com/security/updates/errata/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/updates/errata/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0578.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected redhat-release package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"redhat-release-5Server-5.6.0.4")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"redhat-release-5Server-5.6.0.4")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"redhat-release-5Server-5.6.0.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
