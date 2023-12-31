#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

exit(0, "Temporarily disabled");

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95048);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-7545");

  script_name(english:"Scientific Linux Security Update : policycoreutils on SL6.x, SL7.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - It was found that the sandbox tool provided in
    policycoreutils was vulnerable to a TIOCSTI ioctl
    attack. A specially crafted program executed via the
    sandbox command could use this flaw to execute arbitrary
    commands in the context of the parent shell, escaping
    the sandbox. (CVE-2016-7545)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1611&L=scientific-linux-errata&F=&S=&P=3343
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6ace62d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"policycoreutils-2.0.83-30.1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"policycoreutils-debuginfo-2.0.83-30.1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"policycoreutils-gui-2.0.83-30.1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"policycoreutils-newrole-2.0.83-30.1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"policycoreutils-python-2.0.83-30.1.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"policycoreutils-sandbox-2.0.83-30.1.el6_8")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"policycoreutils-2.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"policycoreutils-debuginfo-2.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"policycoreutils-devel-2.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"policycoreutils-gui-2.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"policycoreutils-newrole-2.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"policycoreutils-python-2.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"policycoreutils-restorecond-2.5-9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"policycoreutils-sandbox-2.5-9.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
