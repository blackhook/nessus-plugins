#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0120 and 
# Oracle Linux Security Advisory ELSA-2013-0120 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68691);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-3417");
  script_bugtraq_id(55066);
  script_xref(name:"RHSA", value:"2013:0120");

  script_name(english:"Oracle Linux 5 : quota (ELSA-2013-0120)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0120 :

An updated quota package that fixes one security issue and multiple
bugs is now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The quota package provides system administration tools for monitoring
and limiting user and group disk usage on file systems.

It was discovered that the rpc.rquotad service did not use
tcp_wrappers correctly. Certain hosts access rules defined in
'/etc/hosts.allow' and '/etc/hosts.deny' may not have been honored,
possibly allowing remote attackers to bypass intended access
restrictions. (CVE-2012-3417)

This issue was discovered by the Red Hat Security Response Team.

This update also fixes the following bugs :

* Prior to this update, values were not properly transported via the
remote procedure call (RPC) and interpreted by the client when
querying the quota usage or limits for network-mounted file systems if
the quota values were 2^32 kilobytes or greater. As a consequence, the
client reported mangled values. This update modifies the underlying
code so that such values are correctly interpreted by the client.
(BZ#667360)

* Prior to this update, warnquota sent messages about exceeded quota
limits from a valid domain name if the warnquota tool was enabled to
send warning e-mails and the superuser did not change the default
warnquota configuration. As a consequence, the recipient could reply
to invalid addresses. This update modifies the default warnquota
configuration to use the reserved example.com. domain. Now, warnings
about exceeded quota limits are sent from the reserved domain that
inform the superuser to change to the correct value. (BZ#680429)

* Previously, quota utilities could not recognize the file system as
having quotas enabled and refused to operate on it due to incorrect
updating of /etc/mtab. This update prefers /proc/mounts to get a list
of file systems with enabled quotas. Now, quota utilities recognize
file systems with enabled quotas as expected. (BZ#689822)

* Prior to this update, the setquota(8) tool on XFS file systems
failed to set disk limits to values greater than 2^31 kilobytes. This
update modifies the integer conversion in the setquota(8) tool to use
a 64-bit variable big enough to store such values. (BZ#831520)

All users of quota are advised to upgrade to this updated package,
which contains backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-January/003197.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected quota package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:quota");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/13");
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
if (rpm_check(release:"EL5", reference:"quota-3.13-8.0.1.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quota");
}
