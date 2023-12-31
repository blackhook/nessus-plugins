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
  script_id(60301);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2006-6303", "CVE-2007-5162", "CVE-2007-5770");

  script_name(english:"Scientific Linux Security Update : ruby on SL5.x, SL4.x i386/x86_64");
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
"A flaw was discovered in the way Ruby's CGI module handles certain
HTTP requests. If a remote attacker sends a specially crafted request,
it is possible to cause the ruby CGI script to enter an infinite loop,
possibly causing a denial of service. (CVE-2006-6303)

An SSL certificate validation flaw was discovered in several Ruby Net
modules. The libraries were not checking the requested host name
against the common name (CN) in the SSL server certificate, possibly
allowing a man in the middle attack. (CVE-2007-5162, CVE-2007-5770)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0711&L=scientific-linux-errata&T=0&P=2626
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca5cf6c7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/13");
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
if (rpm_check(release:"SL4", reference:"irb-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-devel-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-docs-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-libs-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-mode-1.8.1-7.EL4.8.1")) flag++;
if (rpm_check(release:"SL4", reference:"ruby-tcltk-1.8.1-7.EL4.8.1")) flag++;

if (rpm_check(release:"SL5", reference:"ruby-1.8.5-5.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-devel-1.8.5-5.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-docs-1.8.5-5.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-irb-1.8.5-5.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-libs-1.8.5-5.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-mode-1.8.5-5.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-rdoc-1.8.5-5.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-ri-1.8.5-5.el5.1")) flag++;
if (rpm_check(release:"SL5", reference:"ruby-tcltk-1.8.5-5.el5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
