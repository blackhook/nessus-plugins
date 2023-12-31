#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1506. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56989);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_xref(name:"RHSA", value:"2011:1506");

  script_name(english:"RHEL 4 : redhat-release (EOL Notice) (RHSA-2011:1506)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the 3-month notification of the End Of Life plans for Red Hat
Enterprise Linux 4.

In accordance with the Red Hat Enterprise Linux Errata Support Policy,
the regular 7 year life cycle of Red Hat Enterprise Linux 4 will end
on February 29, 2012.

After this date, Red Hat will discontinue the regular subscription
services for Red Hat Enterprise Linux 4. Therefore, new bug fix,
enhancement, and security errata updates, as well as technical support
services will no longer be available for the following products :

* Red Hat Enterprise Linux AS 4 * Red Hat Enterprise Linux ES 4 * Red
Hat Enterprise Linux WS 4 * Red Hat Enterprise Linux Extras 4 * Red
Hat Desktop 4 * Red Hat Global File System 4 * Red Hat Cluster Suite 4

Customers still running production workloads on Red Hat Enterprise
Linux 4 are advised to begin planning the upgrade to Red Hat
Enterprise Linux 5 or 6. Active subscribers of Red Hat Enterprise
Linux already have access to all currently maintained versions of Red
Hat Enterprise Linux, as part of their subscription without additional
fees.

For customers who are unable to migrate off Red Hat Enterprise Linux 4
before its end-of-life date, Red Hat intends to offer a limited,
optional extension program. For more information, contact your Red Hat
sales representative or channel partner.

Details of the Red Hat Enterprise Linux life cycle can be found on the
Red Hat website:
https://access.redhat.com/support/policy/updates/errata/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/support/policy/updates/errata/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1506.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected redhat-release package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL4", reference:"redhat-release-4AS-10.3")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"redhat-release-4WS-10.3")) flag++;
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"redhat-release-4ES-10.3")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"redhat-release-4ES-10.3")) flag++;
if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"redhat-release-4WS-10.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
