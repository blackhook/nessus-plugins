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
  script_id(85199);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-1774");

  script_name(english:"Scientific Linux Security Update : libreoffice on SL6.x i386/x86_64 (20150722)");
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
"A flaw was found in the way the LibreOffice HWP (Hangul Word
Processor) file filter processed certain HWP documents. An attacker
able to trick a user into opening a specially crafted HWP document
could possibly use this flaw to execute arbitrary code with the
privileges of the user opening that document. (CVE-2015-1774)

The libreoffice packages have been upgraded to upstream version
4.2.8.2, which provides a number of bug fixes and enhancements over
the previous version, including :

  - OpenXML interoperability has been improved.

  - This update adds additional statistics functions to the
    Calc application, thus improving interoperability with
    Microsoft Excel and its 'Analysis ToolPak' add-in.

  - Various performance improvements have been implemented
    in Calc.

  - This update adds new import filters for importing files
    from the Appple Keynote and Abiword applications.

  - The export filter for the MathML markup language has
    been improved.

  - This update adds a new start screen that includes
    thumbnails of recently opened documents.

  - A visual clue is now displayed in the Slide Sorter
    window for slides with transitions or animations.

  - This update improves trend lines in charts.

  - LibreOffice now supports BCP 47 language tags."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=5487
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?335b4d81"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:autocorr-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-gdb-debug-support");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-glade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-pt-BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-pt-PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-zh-Hans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-zh-Hant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-opensymbol-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-rhino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreoffice-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"autocorr-af-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-bg-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ca-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-cs-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-da-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-de-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-en-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-es-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fa-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fi-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-fr-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ga-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-hr-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-hu-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-is-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-it-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ja-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ko-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-lb-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-lt-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-mn-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-nl-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-pl-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-pt-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ro-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-ru-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sk-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sl-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sr-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-sv-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-tr-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-vi-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"autocorr-zh-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-base-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-bsh-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-calc-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-core-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-debuginfo-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-draw-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-emailmerge-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-filters-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-gdb-debug-support-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-glade-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-graphicfilter-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-headless-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-impress-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-af-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ar-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-as-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-bg-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-bn-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ca-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-cs-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-cy-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-da-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-de-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-dz-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-el-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-en-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-es-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-et-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-eu-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-fi-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-fr-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ga-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-gl-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-gu-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-he-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hi-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hr-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-hu-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-it-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ja-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-kn-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ko-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-lt-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-mai-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ml-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-mr-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ms-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nb-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nl-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nn-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nr-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-nso-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-or-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pa-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pl-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pt-BR-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-pt-PT-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ro-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ru-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sk-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sl-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sr-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ss-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-st-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-sv-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ta-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-te-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-th-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-tn-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-tr-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ts-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-uk-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ur-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-ve-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-xh-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zh-Hans-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zh-Hant-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-langpack-zu-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-librelogo-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-math-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-nlpsolver-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-ogltrans-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-opensymbol-fonts-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-pdfimport-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-pyuno-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-rhino-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-sdk-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-sdk-doc-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-ure-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-wiki-publisher-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-writer-4.2.8.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreoffice-xsltfilter-4.2.8.2-11.el6")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "autocorr-af / autocorr-bg / autocorr-ca / autocorr-cs / autocorr-da / etc");
}
