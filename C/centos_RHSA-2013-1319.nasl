#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1319 and 
# CentOS Errata and Security Advisory 2013:1319 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79151);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-0219");
  script_bugtraq_id(57539);
  script_xref(name:"RHSA", value:"2013:1319");

  script_name(english:"CentOS 5 : sssd (CESA-2013:1319)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sssd packages that fix one security issue and several bugs are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

SSSD (System Security Services Daemon) provides a set of daemons to
manage access to remote directories and authentication mechanisms. It
provides NSS (Name Service Switch) and PAM (Pluggable Authentication
Modules) interfaces toward the system and a pluggable back end system
to connect to multiple different account sources.

A race condition was found in the way SSSD copied and removed user
home directories. A local attacker who is able to write into the home
directory of a different user who is being removed could use this flaw
to perform symbolic link attacks, possibly allowing them to modify and
delete arbitrary files with the privileges of the root user.
(CVE-2013-0219)

The CVE-2013-0219 issue war discovered by Florian Weimer of the Red
Hat Product Security Team.

This update also fixes the following bugs :

* After a paging control was used, memory in the sssd_be process was
never freed which led to the growth of the sssd_be process memory
usage over time. To fix this bug, the paging control was deallocated
after use, and thus the memory usage of the sssd_be process no longer
grows. (BZ#820908)

* If the sssd_be process was terminated and recreated while there were
authentication requests pending, the sssd_pam process did not recover
correctly and did not reconnect to the new sssd_be process.
Consequently, the sssd_pam process was seemingly blocked and did not
accept any new authentication requests. The sssd_pam process has been
fixes so that it reconnects to the new instance of the sssd_be process
after the original one terminated unexpectedly. Even after a crash and
reconnect, the sssd_pam process now accepts new authentication
requests. (BZ#882414)

* When the sssd_be process hung for a while, it was terminated and a
new instance was created. If the old instance did not respond to the
TERM signal and continued running, SSSD terminated unexpectedly. As a
consequence, the user could not log in. SSSD now keeps track of
sssd_be subprocesses more effectively, making the restarts of sssd_be
more reliable in such scenarios. Users can now log in whenever the
sssd_be is restarted and becomes unresponsive. (BZ#886165)

* In case the processing of an LDAP request took longer than the
client timeout upon completing the request (60 seconds by default),
the PAM client could have accessed memory that was previously freed
due to the client timeout being reached. As a result, the sssd_pam
process terminated unexpectedly with a segmentation fault. SSSD now
ignores an LDAP request result when it detects that the set timeout of
this request has been reached. The sssd_pam process no longer crashes
in the aforementioned scenario. (BZ#923813)

* When there was a heavy load of users and groups to be saved in
cache, SSSD experienced a timeout. Consequently, NSS did not start the
backup process properly and it was impossible to log in. A patch has
been provided to fix this bug. The SSSD daemon now remains responsive
and the login continues as expected. (BZ#805729)

* SSSD kept the file descriptors to the log files open. Consequently,
on occasions like moving the actual log file and restarting the back
end, SSSD still kept the file descriptors open. SSSD now closes the
file descriptor after the child process execution; after a successful
back end start, the file descriptor to log files is closed.
(BZ#961680)

* While performing access control in the Identity Management back end,
SSSD erroneously downloaded the 'member' attribute from the server and
then attempted to use it in the cache verbatim. Consequently, the
cache attempted to use the 'member' attribute values as if they were
pointing to the local cache which was CPU intensive. The member
attribute when processing host groups is no longer downloaded and
processed. Moreover, the login process is reasonably fast even with
large host groups. (BZ#979047)

All sssd users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-October/000876.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?686ea64e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0219");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libipa_hbac-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"libipa_hbac-1.5.1-70.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libipa_hbac-devel-1.5.1-70.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libipa_hbac-python-1.5.1-70.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"sssd-1.5.1-70.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"sssd-client-1.5.1-70.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"sssd-tools-1.5.1-70.el5")) flag++;


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
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libipa_hbac-python / sssd / etc");
}
