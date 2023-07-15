#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2369 and 
# CentOS Errata and Security Advisory 2015:2369 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87153);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-3248");
  script_xref(name:"RHSA", value:"2015:2369");

  script_name(english:"CentOS 7 : openhpi (CESA-2015:2369)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openhpi packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

OpenHPI is an open source project created with the intent of providing
an implementation of the SA Forum's Hardware Platform Interface (HPI).
HPI provides an abstracted interface to managing computer hardware,
typically for chassis and rack based servers. HPI includes resource
modeling, access to and control over sensor, control, watchdog, and
inventory data associated with resources, abstracted System Event Log
interfaces, hardware events and alerts, and a managed hotswap
interface.

It was found that the '/var/lib/openhpi' directory provided by OpenHPI
used world-writeable and world-readable permissions. A local user
could use this flaw to view, modify, and delete OpenHPI-related data,
or even fill up the storage device hosting the /var/lib directory.
(CVE-2015-3248)

This issue was discovered by Marko Myllynen of Red Hat.

The openhpi packages have been upgraded to upstream version 3.4.0,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#1127908)

This update also fixes the following bug :

* Network timeouts were handled incorrectly in the openhpid daemon. As
a consequence, network connections could fail when external plug-ins
were used. With this update, handling of network socket timeouts has
been improved in openhpid, and the described problem no longer occurs.
(BZ#1208127)

All openhpi users are advised to upgrade to these updated packages,
which correct these issues and add these enhancements."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2015-November/002515.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?23c1fa60"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openhpi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3248");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openhpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openhpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openhpi-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openhpi-3.4.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openhpi-devel-3.4.0-2.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"openhpi-libs-3.4.0-2.el7")) flag++;


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
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openhpi / openhpi-devel / openhpi-libs");
}
