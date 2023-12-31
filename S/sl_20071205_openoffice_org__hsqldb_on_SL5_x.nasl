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
  script_id(60324);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2003-0845", "CVE-2007-4575");

  script_name(english:"Scientific Linux Security Update : openoffice.org, hsqldb on SL5.x i386/x86_64");
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
"It was discovered that HSQLDB could allow the execution of arbitrary
public static Java methods. A carefully crafted odb file opened in
OpenOffice.org Base could execute arbitrary commands with the
permissions of the user running OpenOffice.org. (CVE-2007-4575)

It was discovered that HSQLDB did not have a password set on the 'sa'
user. If HSQLDB has been configured as a service, a remote attacker
who could connect to the HSQLDB port (tcp 9001) could execute
arbitrary SQL commands. (CVE-2003-0845)

Note that in Scientific Linux 5, HSQLDB is not enabled as a service by
default, and needs manual configuration in order to work as a service."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind0712&L=scientific-linux-errata&T=0&P=1009
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a005a6e6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/05");
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
if (rpm_check(release:"SL5", reference:"hsqldb-1.8.0.4-3jpp.6")) flag++;
if (rpm_check(release:"SL5", reference:"hsqldb-demo-1.8.0.4-3jpp.6")) flag++;
if (rpm_check(release:"SL5", reference:"hsqldb-javadoc-1.8.0.4-3jpp.6")) flag++;
if (rpm_check(release:"SL5", reference:"hsqldb-manual-1.8.0.4-3jpp.6")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-base-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-calc-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-core-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-draw-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-emailmerge-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-graphicfilter-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-impress-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-javafilter-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-af_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ar-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-as_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-bg_BG-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-bn-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ca_ES-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-cs_CZ-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-cy_GB-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-da_DK-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-de-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-el_GR-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-es-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-et_EE-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-eu_ES-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-fi_FI-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-fr-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ga_IE-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-gl_ES-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-gu_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-he_IL-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hi_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hr_HR-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-hu_HU-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-it-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ja_JP-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-kn_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ko_KR-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-lt_LT-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ml_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-mr_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ms_MY-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nb_NO-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nl-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nn_NO-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nr_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-nso_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-or_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pa_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pl_PL-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pt_BR-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-pt_PT-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ru-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sk_SK-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sl_SI-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sr_CS-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ss_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-st_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-sv-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ta_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-te_IN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-th_TH-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-tn_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-tr_TR-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ts_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ur-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-ve_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-xh_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zh_CN-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zh_TW-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-langpack-zu_ZA-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-math-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-pyuno-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-testtools-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-writer-2.0.4-5.4.25")) flag++;
if (rpm_check(release:"SL5", reference:"openoffice.org-xsltfilter-2.0.4-5.4.25")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
