#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:2885 and 
# Oracle Linux Security Advisory ELSA-2019-2885 respectively.
#

include("compat.inc");

if (description)
{
  script_id(129264);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/24");

  script_cve_id("CVE-2019-11500");
  script_xref(name:"RHSA", value:"2019:2885");

  script_name(english:"Oracle Linux 6 : dovecot (ELSA-2019-2885)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:2885 :

An update for dovecot is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Dovecot is an IMAP server for Linux and other UNIX-like systems,
written primarily with security in mind. It also contains a small POP3
server, and supports e-mail in either the maildir or mbox format. The
SQL drivers and authentication plug-ins are provided as subpackages.

Security Fix(es) :

* dovecot: improper NULL byte handling in IMAP and ManageSieve
protocol parsers leads to out of bounds writes (CVE-2019-11500)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-September/009203.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dovecot packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dovecot-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dovecot-pigeonhole");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"EL6", reference:"dovecot-2.0.9-22.el6_10.1")) flag++;
if (rpm_check(release:"EL6", reference:"dovecot-devel-2.0.9-22.el6_10.1")) flag++;
if (rpm_check(release:"EL6", reference:"dovecot-mysql-2.0.9-22.el6_10.1")) flag++;
if (rpm_check(release:"EL6", reference:"dovecot-pgsql-2.0.9-22.el6_10.1")) flag++;
if (rpm_check(release:"EL6", reference:"dovecot-pigeonhole-2.0.9-22.el6_10.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dovecot / dovecot-devel / dovecot-mysql / dovecot-pgsql / etc");
}
