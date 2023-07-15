#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1242 and 
# CentOS Errata and Security Advisory 2011:1242 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56071);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_xref(name:"RHSA", value:"2011:1242");

  script_name(english:"CentOS 4 / 5 : firefox / xulrunner (CESA-2011:1242)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix one security issue are now available
for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

It was found that a Certificate Authority (CA) issued a fraudulent
HTTPS certificate. This update renders any HTTPS certificates signed
by that CA as untrusted, except for a select few. The now untrusted
certificates that were issued before July 1, 2011 can be manually
re-enabled and used again at your own risk in Firefox; however,
affected certificates issued after this date cannot be re-enabled or
used. (BZ#734316)

All Firefox users should upgrade to these updated packages, which
contain a backported patch. After installing the update, Firefox must
be restarted for the changes to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017714.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?669cfb18"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017715.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?164653ca"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/018056.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47b55273"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/018057.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8994fb5d"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000194.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f3587676"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000195.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4243b83"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or xulrunner packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.6.20-3.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.6.20-3.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.2.20-3.el5_7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.2.20-3.el5_7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / xulrunner / xulrunner-devel");
}
