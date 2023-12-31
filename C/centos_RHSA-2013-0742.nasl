#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0742 and 
# CentOS Errata and Security Advisory 2013:0742 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(65987);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-1897");
  script_bugtraq_id(59026);
  script_xref(name:"RHSA", value:"2013:0742");

  script_name(english:"CentOS 6 : 389-ds-base (CESA-2013:0742)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated 389-ds-base packages that fix one security issue and several
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The 389 Directory Server is an LDAPv3 compliant server. The base
packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

It was found that the 389 Directory Server did not properly restrict
access to entries when the 'nsslapd-allow-anonymous-access'
configuration setting was set to 'rootdse'. An anonymous user could
connect to the LDAP database and, if the search scope is set to BASE,
obtain access to information outside of the rootDSE. (CVE-2013-1897)

This issue was discovered by Martin Kosek of Red Hat.

This update also fixes the following bugs :

* Previously, the schema-reload plug-in was not thread-safe.
Consequently, executing the schema-reload.pl script under heavy load
could have caused the ns-slapd process to terminate unexpectedly with
a segmentation fault. Currently, the schema-reload plug-in is
re-designed so that it is thread-safe, and the schema-reload.pl script
can be executed along with other LDAP operations. (BZ#929107)

* An out of scope problem for a local variable, in some cases, caused
the modrdn operation to terminate unexpectedly with a segmentation
fault. This update declares the local variable at the proper place of
the function so it does not go out of scope, and the modrdn operation
no longer crashes. (BZ#929111)

* A task manually constructed an exact value to be removed from the
configuration if the 'replica-force-cleaning' option was used.
Consequently, the task configuration was not cleaned up, and every
time the server was restarted, the task behaved in the described
manner. This update searches the configuration for the exact value to
delete, instead of manually building the value, and the task does not
restart when the server is restarted. (BZ#929114)

* Previously, a NULL pointer dereference could have occurred when
attempting to get effective rights on an entry that did not exist,
leading to an unexpected termination due to a segmentation fault. This
update checks for NULL entry pointers and returns the appropriate
error. Now, attempts to get effective rights on an entry that does not
exist no longer causes crashes, and the server returns the appropriate
error message. (BZ#929115)

* A problem in the lock timing in the DNA plug-in caused a deadlock if
the DNA operation was executed with other plug-ins. This update moves
the release timing of the problematic lock, and the DNA plug-in does
not cause the deadlock. (BZ#929196)

All 389-ds-base users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
After installing this update, the 389 server service will be restarted
automatically."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-April/019689.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9e7f1bf7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1897");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/17");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-1.2.11.15-14.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-devel-1.2.11.15-14.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-libs-1.2.11.15-14.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs");
}
