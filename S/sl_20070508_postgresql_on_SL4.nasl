#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(60176);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-2138");

  script_name(english:"Scientific Linux Security Update : postgresql on SL4 i386,x86_64, SL5 i386");
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
"Updated postgresql packages that fix several security issues are now
available.

A flaw was found in the way PostgreSQL allows authenticated users to
execute security-definer functions. It was possible for an
unprivileged user to execute arbitrary code with the privileges of the
security-definer function. (CVE-2007-2138)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0705&L=scientific-linux-errata&T=0&P=74
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7546ff6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL4", reference:"postgresql-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-contrib-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-devel-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-docs-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-jdbc-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-libs-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-pl-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-python-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-server-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-tcl-7.4.17-1.RHEL4.1")) flag++;
if (rpm_check(release:"SL4", reference:"postgresql-test-7.4.17-1.RHEL4.1")) flag++;

if (rpm_check(release:"SL5", cpu:"i386", reference:"postgresql-8.1.9-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"postgresql-contrib-8.1.9-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"postgresql-devel-8.1.9-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"postgresql-docs-8.1.9-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"postgresql-libs-8.1.9-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"postgresql-pl-8.1.9-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"postgresql-python-8.1.9-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"postgresql-server-8.1.9-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"postgresql-tcl-8.1.9-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"postgresql-test-8.1.9-1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
