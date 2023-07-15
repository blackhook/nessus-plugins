#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0580 and 
# CentOS Errata and Security Advisory 2013:0580 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65031);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-5519");
  script_bugtraq_id(56494);
  script_xref(name:"RHSA", value:"2013:0580");

  script_name(english:"CentOS 5 / 6 : cups (CESA-2013:0580)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for Linux, UNIX, and similar operating systems.

It was discovered that CUPS administrative users (members of the
SystemGroups groups) who are permitted to perform CUPS configuration
changes via the CUPS web interface could manipulate the CUPS
configuration to gain unintended privileges. Such users could read or
write arbitrary files with the privileges of the CUPS daemon, possibly
allowing them to run arbitrary code with root privileges.
(CVE-2012-5519)

After installing this update, the ability to change certain CUPS
configuration directives remotely will be disabled by default. The
newly introduced ConfigurationChangeRestriction directive can be used
to enable the changing of the restricted directives remotely. Refer to
Red Hat Bugzilla bug 875898 for more details and the list of
restricted directives.

All users of cups are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue. After
installing this update, the cupsd daemon will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4efac01"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-March/019616.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26cc1f4c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-March/000811.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1af0615a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5519");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"cups-1.3.7-30.el5_9.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-devel-1.3.7-30.el5_9.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-libs-1.3.7-30.el5_9.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-lpd-1.3.7-30.el5_9.3")) flag++;

if (rpm_check(release:"CentOS-6", reference:"cups-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-devel-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-libs-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-lpd-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-php-1.4.2-50.el6_4.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-devel / cups-libs / cups-lpd / cups-php");
}
