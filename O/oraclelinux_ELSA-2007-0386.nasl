#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0386 and 
# Oracle Linux Security Advisory ELSA-2007-0386 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67505);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-5297", "CVE-2007-1558", "CVE-2007-2683");
  script_bugtraq_id(23257);
  script_xref(name:"RHSA", value:"2007:0386");

  script_name(english:"Oracle Linux 3 / 4 / 5 : mutt (ELSA-2007-0386)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0386 :

An updated mutt package that fixes several security bugs is now
available for Red Hat Enterprise Linux 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mutt is a text-mode mail user agent.

A flaw was found in the way Mutt used temporary files on NFS file
systems. Due to an implementation issue in the NFS protocol, Mutt was
not able to exclusively open a new file. A local attacker could
conduct a time-dependent attack and possibly gain access to e-mail
attachments opened by a victim. (CVE-2006-5297)

A flaw was found in the way Mutt processed certain APOP authentication
requests. By sending certain responses when mutt attempted to
authenticate against an APOP server, a remote attacker could
potentially acquire certain portions of a user's authentication
credentials. (CVE-2007-1558)

A flaw was found in the way Mutt handled certain characters in gecos
fields which could lead to a buffer overflow. The gecos field is an
entry in the password database typically used to record general
information about the user. A local attacker could give themselves a
carefully crafted 'Real Name' which could execute arbitrary code if a
victim uses Mutt and expands the attackers alias. (CVE-2007-2683)

All users of mutt should upgrade to this updated package, which
contains a backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000167.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000168.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-June/000216.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mutt package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mutt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/26");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3 / 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"mutt-1.4.1-5.el3")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"mutt-1.4.1-5.el3")) flag++;

if (rpm_check(release:"EL4", cpu:"i386", reference:"mutt-1.4.1-12.0.3.el4")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"mutt-1.4.1-12.0.3.el4")) flag++;

if (rpm_check(release:"EL5", reference:"mutt-1.4.2.2-3.0.2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mutt");
}
