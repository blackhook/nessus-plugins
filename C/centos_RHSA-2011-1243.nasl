#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1243 and 
# CentOS Errata and Security Advisory 2011:1243 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56072);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_xref(name:"RHSA", value:"2011:1243");

  script_name(english:"CentOS 4 / 5 : thunderbird (CESA-2011:1243)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes one security issue is now
available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact.

Mozilla Thunderbird is a standalone mail and newsgroup client.

It was found that a Certificate Authority (CA) issued a fraudulent
HTTPS certificate. This update renders any HTTPS certificates signed
by that CA as untrusted, except for a select few. The now untrusted
certificates that were issued before July 1, 2011 can be manually
re-enabled and used again at your own risk in Thunderbird; however,
affected certificates issued after this date cannot be re-enabled or
used. (BZ#734316)

All Thunderbird users should upgrade to this updated package, which
resolves this issue. All running instances of Thunderbird must be
restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017712.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ae2f28c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017713.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?111904a3"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/018008.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4ba506c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/018009.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe4f4625"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000170.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d67fdb58"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000171.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?713a0237"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/05");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"thunderbird-1.5.0.12-42.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"thunderbird-1.5.0.12-42.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"thunderbird-2.0.0.24-24.el5.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
