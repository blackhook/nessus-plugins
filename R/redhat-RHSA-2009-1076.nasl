#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1076. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38983);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_xref(name:"RHSA", value:"2009:1076");

  script_xref(name:"IAVA", value:"0001-A-0638");

  script_name(english:"RHEL 2.1 : redhat-release (EOL Notice) (RHSA-2009:1076)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is the End Of Life notification for Red Hat Enterprise Linux 2.1.

In accordance with the Red Hat Enterprise Linux Errata Support Policy,
the 7 year life cycle of Red Hat Enterprise Linux 2.1 has ended.

Red Hat has discontinued the technical support services, bug fix,
enhancement, and security errata updates for the following versions :

* Red Hat Enterprise Linux AS 2.1 * Red Hat Enterprise Linux ES 2.1 *
Red Hat Enterprise Linux WS 2.1 * Red Hat Linux Advanced Server 2.1 *
Red Hat Linux Advanced Workstation 2.1

Servers subscribed to Red Hat Enterprise Linux 2.1 channels on the Red
Hat Network will become unsubscribed. As a benefit of the Red Hat
subscription model, those subscriptions can be used to entitle any
system on any currently supported release of Red Hat Enterprise Linux.
Details of the Red Hat Enterprise Linux life cycle for all releases
can be found on the Red Hat website :

http://www.redhat.com/security/updates/errata/

As part of the End Of Life process, the Red Hat Network will cease to
carry the Red Hat Enterprise Linux 2.1 binaries. The source code and
security advisories will continue to be available."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/security/updates/errata/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-1076.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected redhat-release-as, redhat-release-es and / or
redhat-release-ws packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-release-ws");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"redhat-release-as-2.1AS-25")) flag++;
if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"redhat-release-es-2.1ES-25")) flag++;
if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"redhat-release-ws-2.1WS-25")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
