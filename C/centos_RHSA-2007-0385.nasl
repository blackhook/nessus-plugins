#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0385 and 
# CentOS Errata and Security Advisory 2007:0385 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25447);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1558");
  script_bugtraq_id(23257);
  script_xref(name:"RHSA", value:"2007:0385");

  script_name(english:"CentOS 3 / 4 / 5 : fetchmail (CESA-2007:0385)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated fetchmail package that fixes a security bug is now
available for Red Hat Enterprise Linux 2.1, 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Fetchmail is a remote mail retrieval and forwarding utility intended
for use over on-demand TCP/IP links, like SLIP or PPP connections.

A flaw was found in the way fetchmail processed certain APOP
authentication requests. By sending certain responses when fetchmail
attempted to authenticate against an APOP server, a remote attacker
could potentially acquire certain portions of a user's authentication
credentials. (CVE-2007-1558)

All users of fetchmail should upgrade to this updated package, which
contains a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013878.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb3cd6d9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013879.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a165db8b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013880.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84a4bc57"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013881.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d50f362"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013883.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2497dd6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013884.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d9b03e5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013908.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d0ab99c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-June/013909.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b56fcee"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fetchmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:fetchmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"fetchmail-6.2.0-3.el3.4")) flag++;

if (rpm_check(release:"CentOS-4", reference:"fetchmail-6.2.5-6.0.1.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"fetchmail-6.3.6-1.0.1.el5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fetchmail");
}
