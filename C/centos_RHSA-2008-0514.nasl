#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0514 and 
# CentOS Errata and Security Advisory 2008:0514 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43691);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-1108", "CVE-2008-1109");
  script_bugtraq_id(29527);
  script_xref(name:"RHSA", value:"2008:0514");

  script_name(english:"CentOS 5 : evolution (CESA-2008:0514)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution packages that fix two buffer overflow
vulnerabilities are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Evolution is the integrated collection of e-mail, calendaring, contact
management, communications and personal information management (PIM)
tools for the GNOME desktop environment.

A flaw was found in the way Evolution parsed iCalendar timezone
attachment data. If the Itip Formatter plug-in was disabled and a user
opened a mail with a carefully crafted iCalendar attachment, arbitrary
code could be executed as the user running Evolution. (CVE-2008-1108)

Note: the Itip Formatter plug-in, which allows calendar information
(attachments with a MIME type of 'text/calendar') to be displayed as
part of the e-mail message, is enabled by default.

A heap-based buffer overflow flaw was found in the way Evolution
parsed iCalendar attachments with an overly long 'DESCRIPTION'
property string. If a user responded to a carefully crafted iCalendar
attachment in a particular way, arbitrary code could be executed as
the user running Evolution. (CVE-2008-1109).

The particular response required to trigger this vulnerability was as
follows :

1. Receive the carefully crafted iCalendar attachment. 2. Accept the
associated meeting. 3. Open the calender the meeting was in. 4. Reply
to the sender.

Red Hat would like to thank Alin Rad Pop of Secunia Research for
responsibly disclosing these issues.

All Evolution users should upgrade to these updated packages, which
contain backported patches which resolves these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/015032.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3df8094"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-June/015033.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb1f237b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-help");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"evolution-2.12.3-8.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"evolution-devel-2.12.3-8.el5_2.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"evolution-help-2.12.3-8.el5_2.2")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution / evolution-devel / evolution-help");
}
