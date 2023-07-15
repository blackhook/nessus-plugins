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
  script_id(61657);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-2642", "CVE-2010-3702", "CVE-2010-3704", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");

  script_name(english:"Scientific Linux Security Update : tetex on SL5.x i386/x86_64 (20120823)");
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
"teTeX is an implementation of TeX. TeX takes a text file and a set of
formatting commands as input, and creates a typesetter-independent
DeVice Independent (DVI) file as output.

teTeX embeds a copy of t1lib to rasterize bitmaps from PostScript Type
1 fonts. The following issues affect t1lib code :

Two heap-based buffer overflow flaws were found in the way t1lib
processed Adobe Font Metrics (AFM) files. If a specially crafted font
file was opened by teTeX, it could cause teTeX to crash or,
potentially, execute arbitrary code with the privileges of the user
running teTeX. (CVE-2010-2642, CVE-2011-0433)

An invalid pointer dereference flaw was found in t1lib. A specially
crafted font file could, when opened, cause teTeX to crash or,
potentially, execute arbitrary code with the privileges of the user
running teTeX. (CVE-2011-0764)

A use-after-free flaw was found in t1lib. A specially crafted font
file could, when opened, cause teTeX to crash or, potentially, execute
arbitrary code with the privileges of the user running teTeX.
(CVE-2011-1553)

An off-by-one flaw was found in t1lib. A specially crafted font file
could, when opened, cause teTeX to crash or, potentially, execute
arbitrary code with the privileges of the user running teTeX.
(CVE-2011-1554)

An out-of-bounds memory read flaw was found in t1lib. A specially
crafted font file could, when opened, cause teTeX to crash.
(CVE-2011-1552)

teTeX embeds a copy of Xpdf, an open source Portable Document Format
(PDF) file viewer, to allow adding images in PDF format to the
generated PDF documents. The following issues affect Xpdf code :

An uninitialized pointer use flaw was discovered in Xpdf. If pdflatex
was used to process a TeX document referencing a specially crafted PDF
file, it could cause pdflatex to crash or, potentially, execute
arbitrary code with the privileges of the user running pdflatex.
(CVE-2010-3702)

An array index error was found in the way Xpdf parsed PostScript Type
1 fonts embedded in PDF documents. If pdflatex was used to process a
TeX document referencing a specially crafted PDF file, it could cause
pdflatex to crash or, potentially, execute arbitrary code with the
privileges of the user running pdflatex. (CVE-2010-3704)

All users of tetex are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=2449
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb75a274"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/24");
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
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"tetex-3.0-33.15.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-afm-3.0-33.15.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-doc-3.0-33.15.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-dvips-3.0-33.15.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-fonts-3.0-33.15.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-latex-3.0-33.15.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"tetex-xdvi-3.0-33.15.el5_8.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-doc / tetex-dvips / tetex-fonts / etc");
}
