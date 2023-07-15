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
  script_id(61287);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-0037");

  script_name(english:"Scientific Linux Security Update : openoffice.org on SL5.x i386/x86_64 (20120322)");
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
"OpenOffice.org is an office productivity suite that includes desktop
applications, such as a word processor, spreadsheet application,
presentation manager, formula editor, and a drawing program.
OpenOffice.org embeds a copy of Raptor, which provides parsers for
Resource Description Framework (RDF) files.

An XML External Entity expansion flaw was found in the way Raptor
processed RDF files. If OpenOffice.org were to open a specially
crafted file (such as an OpenDocument Format or OpenDocument
Presentation file), it could possibly allow a remote attacker to
obtain a copy of an arbitrary local file that the user running
OpenOffice.org had access to. A bug in the way Raptor handled external
entities could cause OpenOffice.org to crash or, possibly, execute
arbitrary code with the privileges of the user running OpenOffice.org.
(CVE-2012-0037)

All OpenOffice.org users are advised to upgrade to these updated
packages, which contain backported patches to correct this issue. All
running instances of OpenOffice.org applications must be restarted for
this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=4437
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?496d5f23"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-as_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-kn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ml_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-mr_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-nr_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-nso_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-or_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ss_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-st_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-tn_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ts_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-ve_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-xh_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openoffice.org-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/22");
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
if (rpm_check(release:"SL5", reference:"openoffice.org-base-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-calc-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-core-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-debuginfo-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-draw-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-emailmerge-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-graphicfilter-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-headless-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-impress-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-javafilter-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-af_ZA-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ar-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-as_IN-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-bg_BG-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-bn-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ca_ES-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-cs_CZ-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-cy_GB-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-da_DK-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-de-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-el_GR-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-es-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-et_EE-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-eu_ES-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-fi_FI-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-fr-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ga_IE-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-gl_ES-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-gu_IN-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-he_IL-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hi_IN-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hr_HR-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hu_HU-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-it-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ja_JP-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-kn_IN-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ko_KR-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-lt_LT-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ml_IN-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-mr_IN-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ms_MY-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nb_NO-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nl-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nn_NO-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nr_ZA-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nso_ZA-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-or_IN-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pa_IN-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pl_PL-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pt_BR-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pt_PT-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ru-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sk_SK-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sl_SI-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sr_CS-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ss_ZA-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-st_ZA-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sv-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ta_IN-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-te_IN-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-th_TH-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-tn_ZA-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-tr_TR-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ts_ZA-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ur-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ve_ZA-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-xh_ZA-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zh_CN-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zh_TW-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zu_ZA-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-math-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-pyuno-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-sdk-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-sdk-doc-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-testtools-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-ure-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-writer-3.1.1-19.10.el5_8.1")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-xsltfilter-3.1.1-19.10.el5_8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org-base / openoffice.org-calc / openoffice.org-core / etc");
}
