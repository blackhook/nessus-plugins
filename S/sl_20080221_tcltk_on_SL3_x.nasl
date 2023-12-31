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
  script_id(60362);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-4772", "CVE-2007-5378", "CVE-2008-0553");

  script_name(english:"Scientific Linux Security Update : tcltk on SL3.x i386/x86_64");
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
"An input validation flaw was discovered in Tk's GIF image handling. A
code-size value read from a GIF image was not properly validated
before being used, leading to a buffer overflow. A specially crafted
GIF file could use this to cause a crash or, potentially, execute code
with the privileges of the application using the Tk graphical toolkit.
(CVE-2008-0553)

A buffer overflow flaw was discovered in Tk's animated GIF image
handling. An animated GIF containing an initial image smaller than
subsequent images could cause a crash or, potentially, execute code
with the privileges of the application using the Tk library.
(CVE-2007-5378)

A flaw in the Tcl regular expression handling engine was discovered by
Will Drewry. This flaw, first discovered in the Tcl regular expression
engine used in the PostgreSQL database server, resulted in an infinite
loop when processing certain regular expressions. (CVE-2007-4772)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0802&L=scientific-linux-errata&T=0&P=1176
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7fc619cf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/21");
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
if (rpm_check(release:"SL3", reference:"expect-5.38.0-92.8")) flag++;
if (rpm_check(release:"SL3", reference:"expect-devel-5.38.0-92.8")) flag++;
if (rpm_check(release:"SL3", reference:"expectk-5.38.0-92.8")) flag++;
if (rpm_check(release:"SL3", reference:"itcl-3.2-92.8")) flag++;
if (rpm_check(release:"SL3", reference:"tcl-8.3.5-92.8")) flag++;
if (rpm_check(release:"SL3", reference:"tcl-devel-8.3.5-92.8")) flag++;
if (rpm_check(release:"SL3", reference:"tcl-html-8.3.5-92.8")) flag++;
if (rpm_check(release:"SL3", reference:"tcllib-1.3-92.8")) flag++;
if (rpm_check(release:"SL3", reference:"tclx-8.3-92.8")) flag++;
if (rpm_check(release:"SL3", reference:"tix-8.1.4-92.8")) flag++;
if (rpm_check(release:"SL3", reference:"tk-8.3.5-92.8")) flag++;
if (rpm_check(release:"SL3", reference:"tk-devel-8.3.5-92.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
