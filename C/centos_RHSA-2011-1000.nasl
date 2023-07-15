#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1000 and 
# CentOS Errata and Security Advisory 2011:1000 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56262);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-3389");
  script_bugtraq_id(44359);
  script_xref(name:"RHSA", value:"2011:1000");

  script_name(english:"CentOS 5 : rgmanager (CESA-2011:1000)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated rgmanager package that fixes one security issue, several
bugs, and adds multiple enhancements is now available for Red Hat
Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The rgmanager package contains the Red Hat Resource Group Manager,
which provides the ability to create and manage high-availability
server applications in the event of system downtime.

It was discovered that certain resource agent scripts set the
LD_LIBRARY_PATH environment variable to an insecure value containing
empty path elements. A local user able to trick a user running those
scripts to run them while working from an attacker-writable directory
could use this flaw to escalate their privileges via a
specially crafted dynamic library. (CVE-2010-3389)

Red Hat would like to thank Raphael Geissert for reporting this issue.

This update also fixes the following bugs :

* The failover domain 'nofailback' option was not honored if a service
was in the 'starting' state. This bug has been fixed. (BZ#669440)

* PID files with white spaces in the file name are now handled
correctly. (BZ#632704)

* The /usr/sbin/rhev-check.sh script can now be used from within Cron.
(BZ#634225)

* The clustat utility now reports the correct version. (BZ#654160)

* The oracledb.sh agent now attempts to try the 'shutdown immediate'
command instead of using the 'shutdown abort' command. (BZ#633992)

* The SAPInstance and SAPDatabase scripts now use proper directory
name quoting so they no longer collide with directory names like '/u'.
(BZ#637154)

* The clufindhostname utility now returns the correct value in all
cases. (BZ#592613)

* The nfsclient resource agent now handles paths with trailing slashes
correctly. (BZ#592624)

* The last owner of a service is now reported correctly after a
failover. (BZ#610483)

* The /usr/share/cluster/fs.sh script no longer runs the 'quotaoff'
command if quotas were not configured. (BZ#637678)

* The 'listen' line in the /etc/httpd/conf/httpd.conf file generated
by the Apache resource agent is now correct. (BZ#675739)

* The tomcat-5 resource agent no longer generates incorrect
configurations. (BZ#637802)

* The time required to stop an NFS resource when the server is
unavailable has been reduced. (BZ#678494)

* When using exclusive prioritization, a higher priority service now
preempts a lower priority service after status check failures.
(BZ#680256)

* The postgres-8 resource agent now correctly detects failed start
operations. (BZ#663827)

* The handling of reference counts passed by rgmanager to resource
agents now works properly, as expected. (BZ#692771)

As well, this update adds the following enhancements :

* It is now possible to disable updates to static routes by the IP
resource agent. (BZ#620700)

* It is now possible to use XFS as a file system within a cluster
service. (BZ#661893)

* It is now possible to use the 'clustat' command as a non-root user,
so long as that user is in the 'root' group. (BZ#510300)

* It is now possible to migrate virtual machines when central
processing is enabled. (BZ#525271)

* The rgmanager init script will now delay after stopping services in
order to allow time for other nodes to restart them. (BZ#619468)

* The handling of failed independent subtrees has been corrected.
(BZ#711521)

All users of Red Hat Resource Group Manager are advised to upgrade to
this updated package, which contains backported patches to correct
these issues and add these enhancements."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017958.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?271005b4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-September/017959.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?527df4dd"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000132.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edde1c15"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2011-September/000133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af063f2d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rgmanager package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rgmanager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"rgmanager-2.0.52-21.el5.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rgmanager");
}
