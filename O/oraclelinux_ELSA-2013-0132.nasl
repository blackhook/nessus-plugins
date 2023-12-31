#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0132 and 
# Oracle Linux Security Advisory ELSA-2013-0132 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68703);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2697");
  script_bugtraq_id(57183);
  script_xref(name:"RHSA", value:"2013:0132");

  script_name(english:"Oracle Linux 5 : autofs (ELSA-2013-0132)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0132 :

An updated autofs package that fixes one security issue, several bugs,
and adds one enhancement is now available for Red Hat Enterprise Linux
5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The autofs utility controls the operation of the automount daemon. The
automount daemon automatically mounts and unmounts file systems.

A bug fix included in RHBA-2012:0264 introduced a denial of service
flaw in autofs. When using autofs with LDAP, a local user could use
this flaw to crash autofs, preventing future mount requests from being
processed until the autofs service was restarted. Note: This flaw did
not impact existing mounts (except for preventing mount expiration).
(CVE-2012-2697)

Red Hat would like to thank Ray Rocker for reporting this issue.

This update also fixes the following bugs :

* The autofs init script sometimes timed out waiting for the automount
daemon to exit and returned a shutdown failure if the daemon failed to
exit in time. To resolve this problem, the amount of time that the
init script waits for the daemon has been increased to allow for cases
where servers are slow to respond or there are many active mounts.
(BZ#585058)

* Due to an omission when backporting a change, autofs attempted to
download the entire LDAP map at startup. This mistake has now been
corrected. (BZ#767428)

* A function to check the validity of a mount location was meant to
check only for a small subset of map location errors. A recent
modification in error reporting inverted a logic test in this
validating function. Consequently, the scope of the test was widened,
which caused the automount daemon to report false positive failures.
With this update, the faulty logic test has been corrected and false
positive failures no longer occur. (BZ#798448)

* When there were many attempts to access invalid or non-existent
keys, the automount daemon used excessive CPU resources. As a
consequence, systems sometimes became unresponsive. The code has been
improved so that automount checks for invalid keys earlier in the
process which has eliminated a significant amount of the processing
overhead. (BZ#847101)

* The auto.master(5) man page did not document the '-t, --timeout'
option in the FORMAT options section. This update adds this
information to the man page. (BZ#859890)

This update also adds the following enhancement :

* Previously, it was not possible to configure separate timeout values
for individual direct map entries in the autofs master map. This
update adds this functionality. (BZ#690404)

All users of autofs are advised to upgrade to this updated package,
which contains backported patches to correct these issues and add this
enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-January/003204.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected autofs package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autofs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"autofs-5.0.1-0.rc2.177.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autofs");
}
