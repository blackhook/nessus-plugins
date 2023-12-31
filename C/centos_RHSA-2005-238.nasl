#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:238 and 
# CentOS Errata and Security Advisory 2005:238 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21799);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0102");
  script_xref(name:"RHSA", value:"2005:238");

  script_name(english:"CentOS 3 : evolution (CESA-2005:238)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution packages that fix various bugs are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Evolution is the GNOME collection of personal information management
(PIM) tools. Evolution includes a mailer, calendar, contact manager,
and communication facility. The tools which make up Evolution are
tightly integrated with one another and act as a seamless personal
information management tool.

A bug was found in Evolution's helper program camel-lock-helper. This
bug could allow a local attacker to gain root privileges if
camel-lock-helper has been built to execute with elevated privileges.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0102 to this issue. On Red Hat Enterprise
Linux, camel-lock-helper is not built to execute with elevated
privileges by default. Please note however that if users have rebuilt
Evolution from the source RPM, as the root user, camel-lock-helper may
be given elevated privileges.

Additionally, these updated packages address the following issues :

-- If evolution ran during a GNOME session, the evolution-wombat
process did not exit when the user logged out of the desktop.

-- For folders marked for Offline Synchronization: if a user moved a
message from a Local Folder to an IMAP folder while in Offline mode,
the message was not present in either folder after returning to Online
mode.

This update fixes this problem. Email messages that have been lost
this way may still be present in the following path :

~/evolution/<NAME_OF_MAIL_STORE>/ \
<path-to-folder-via-subfolder-directories>/ \
<temporary-uid-of-message>

If this bug has affected you it may be possible to recover data by
examining the contents of this directory.

All users of evolution should upgrade to these updated packages, which
resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011715.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?899943eb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e90817a5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011727.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f2d6ab4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011735.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7aacb5fe"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011736.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1066cb9d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"evolution-1.4.5-14")) flag++;
if (rpm_check(release:"CentOS-3", reference:"evolution-devel-1.4.5-14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution / evolution-devel");
}
