#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0663 and 
# Oracle Linux Security Advisory ELSA-2013-0663 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68793);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0287");
  script_xref(name:"RHSA", value:"2013:0663");

  script_name(english:"Oracle Linux 6 : sssd (ELSA-2013-0663)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0663 :

Updated sssd packages that fix one security issue and two bugs are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

SSSD (System Security Services Daemon) provides a set of daemons to
manage access to remote directories and authentication mechanisms. It
provides NSS (Name Service Switch) and PAM (Pluggable Authentication
Modules) interfaces toward the system and a pluggable back end system
to connect to multiple different account sources.

When SSSD was configured as a Microsoft Active Directory client by
using the new Active Directory provider (introduced in
RHSA-2013:0508), the Simple Access Provider ('access_provider =
simple' in '/etc/sssd/sssd.conf') did not handle access control
correctly. If any groups were specified with the 'simple_deny_groups'
option (in sssd.conf), all users were permitted access.
(CVE-2013-0287)

The CVE-2013-0287 issue was discovered by Kaushik Banerjee of Red Hat.

This update also fixes the following bugs :

* If a group contained a member whose Distinguished Name (DN) pointed
out of any of the configured search bases, the search request that was
processing this particular group never ran to completion. To the user,
this bug manifested as a long timeout between requesting the group
data and receiving the result. A patch has been provided to address
this bug and SSSD now processes group search requests without delays.
(BZ#907362)

* The pwd_expiration_warning should have been set for seven days, but
instead it was set to zero for Kerberos. This incorrect zero setting
returned the 'always display warning if the server sends one' error
message and users experienced problems in environments like IPA or
Active Directory. Currently, the value setting for Kerberos is
modified and this issue no longer occurs. (BZ#914671)

All users of sssd are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-March/003377.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libipa_hbac-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libsss_sudo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/19");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"libipa_hbac-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"libipa_hbac-devel-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"libipa_hbac-python-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"libsss_autofs-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"libsss_idmap-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"libsss_idmap-devel-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"libsss_sudo-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"libsss_sudo-devel-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"sssd-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"sssd-client-1.9.2-82.4.el6_4")) flag++;
if (rpm_check(release:"EL6", reference:"sssd-tools-1.9.2-82.4.el6_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libipa_hbac-python / etc");
}
