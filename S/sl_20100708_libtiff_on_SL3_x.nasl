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
  script_id(60812);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-1411", "CVE-2010-2481", "CVE-2010-2483", "CVE-2010-2595", "CVE-2010-2597", "CVE-2010-2598");

  script_name(english:"Scientific Linux Security Update : libtiff on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"Multiple integer overflow flaws, leading to a buffer overflow, were
discovered in libtiff. An attacker could use these flaws to create a
specially crafted TIFF file that, when opened, would cause an
application linked against libtiff to crash or, possibly, execute
arbitrary code. (CVE-2010-1411)

Multiple input validation flaws were discovered in libtiff. An
attacker could use these flaws to create a specially crafted TIFF file
that, when opened, would cause an application linked against libtiff
to crash. (CVE-2010-2481, CVE-2010-2483, CVE-2010-2595, CVE-2010-2597)
- SL4, SL5

An input validation flaw was discovered in libtiff. An attacker could
use this flaw to create a specially crafted TIFF file that, when
opened, would cause an application linked against libtiff to crash.
(CVE-2010-2598) - SL3

All runningapplications linked against libtiff must be restarted for
this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1007&L=scientific-linux-errata&T=0&P=686
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6cb45bb1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff and / or libtiff-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
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
if (rpm_check(release:"SL3", reference:"libtiff-3.5.7-34.el3")) flag++;
if (rpm_check(release:"SL3", reference:"libtiff-devel-3.5.7-34.el3")) flag++;

if (rpm_check(release:"SL4", reference:"libtiff-3.6.1-12.el4_8.5")) flag++;
if (rpm_check(release:"SL4", reference:"libtiff-devel-3.6.1-12.el4_8.5")) flag++;

if (rpm_check(release:"SL5", reference:"libtiff-3.8.2-7.el5_5.5")) flag++;
if (rpm_check(release:"SL5", reference:"libtiff-devel-3.8.2-7.el5_5.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
