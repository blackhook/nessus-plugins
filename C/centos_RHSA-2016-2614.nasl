#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2614 and 
# CentOS Errata and Security Advisory 2016:2614 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95353);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-7035");
  script_xref(name:"RHSA", value:"2016:2614");

  script_name(english:"CentOS 7 : pacemaker (CESA-2016:2614)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for pacemaker is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Pacemaker cluster resource manager is a collection of technologies
working together to provide data integrity and the ability to maintain
application availability in the event of a failure.

Security Fix(es) :

* An authorization flaw was found in Pacemaker, where it did not
properly guard its IPC interface. An attacker with an unprivileged
account on a Pacemaker node could use this flaw to, for example, force
the Local Resource Manager daemon to execute a script as root and
thereby gain root access on the machine. (CVE-2016-7035)

This issue was discovered by Jan 'poki' Pokorny (Red Hat) and Alain
Moulle (ATOS/BULL).

Bug Fix(es) :

* The version of Pacemaker in Red Hat Enterprise Linux 7.3
incorporated an increase in the version number of the remote node
protocol. Consequently, cluster nodes running Pacemaker in Red Hat
Enterprise Linux 7.3 and remote nodes running earlier versions of Red
Hat Enterprise Linux were not able to communicate with each other
unless special precautions were taken. This update preserves the
rolling upgrade capability. (BZ#1389023)"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-November/003685.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6fdcfca3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pacemaker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7035");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-nagios-plugins-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-cli-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-cluster-libs-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-cts-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-doc-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-libs-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-libs-devel-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-nagios-plugins-metadata-1.1.15-11.el7_3.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pacemaker-remote-1.1.15-11.el7_3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pacemaker / pacemaker-cli / pacemaker-cluster-libs / pacemaker-cts / etc");
}
