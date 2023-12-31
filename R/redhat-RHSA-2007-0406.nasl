#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0406. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25520);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-0245");
  script_bugtraq_id(24450);
  script_xref(name:"RHSA", value:"2007:0406");

  script_name(english:"RHEL 3 / 4 / 5 : openoffice.org (RHSA-2007:0406)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openoffice.org packages to correct a security issue are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenOffice.org is an office productivity suite that includes desktop
applications such as a word processor, spreadsheet, presentation
manager, formula editor, and drawing program.

A heap overflow flaw was found in the RTF import filer. An attacker
could create a carefully crafted RTF file that could cause
OpenOffice.org to crash or possibly execute arbitrary code if the file
was opened by a victim. (CVE-2007-0245)

All users of OpenOffice.org are advised to upgrade to these updated
packages, which contain a backported fix to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-0245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2007:0406"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-as_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-kn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ml_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-mr_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nr_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-nso_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-or_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ss_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-st_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-tn_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ts_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-ve_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-xh_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openoffice.org2-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0406";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"openoffice.org-1.1.2-39.2.0.EL3")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"openoffice.org-i18n-1.1.2-39.2.0.EL3")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"openoffice.org-libs-1.1.2-39.2.0.EL3")) flag++;


  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-1.1.5-10.6.0.1.EL4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-i18n-1.1.5-10.6.0.1.EL4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-kde-1.1.5-10.6.0.1.EL4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org-libs-1.1.5-10.6.0.1.EL4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-base-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-calc-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-core-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-draw-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-emailmerge-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-graphicfilter-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-impress-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-javafilter-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-af_ZA-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ar-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-bg_BG-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-bn-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ca_ES-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-cs_CZ-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-cy_GB-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-da_DK-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-de-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-el_GR-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-es-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-et_EE-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-eu_ES-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-fi_FI-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-fr-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ga_IE-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-gl_ES-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-gu_IN-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-he_IL-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-hi_IN-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-hr_HR-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-hu_HU-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-it-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ja_JP-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ko_KR-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-lt_LT-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ms_MY-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-nb_NO-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-nl-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-nn_NO-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-pa_IN-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-pl_PL-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-pt_BR-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-pt_PT-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ru-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-sk_SK-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-sl_SI-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-sr_CS-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-sv-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-ta_IN-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-th_TH-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-tr_TR-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-zh_CN-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-zh_TW-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-langpack-zu_ZA-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-math-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-pyuno-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-testtools-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-writer-2.0.4-5.7.0.1.0")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"openoffice.org2-xsltfilter-2.0.4-5.7.0.1.0")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-base-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-base-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-calc-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-calc-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-core-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-core-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-draw-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-draw-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-emailmerge-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-emailmerge-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-graphicfilter-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-graphicfilter-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-impress-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-impress-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-javafilter-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-javafilter-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-af_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-af_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ar-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ar-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-as_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-as_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-bg_BG-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-bg_BG-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-bn-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-bn-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ca_ES-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ca_ES-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-cs_CZ-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-cs_CZ-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-cy_GB-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-cy_GB-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-da_DK-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-da_DK-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-de-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-de-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-el_GR-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-el_GR-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-es-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-es-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-et_EE-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-et_EE-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-eu_ES-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-eu_ES-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-fi_FI-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-fi_FI-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-fr-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-fr-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ga_IE-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ga_IE-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-gl_ES-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-gl_ES-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-gu_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-gu_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-he_IL-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-he_IL-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-hi_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-hi_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-hr_HR-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-hr_HR-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-hu_HU-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-hu_HU-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-it-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-it-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ja_JP-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ja_JP-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-kn_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-kn_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ko_KR-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ko_KR-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-lt_LT-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-lt_LT-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ml_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ml_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-mr_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-mr_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ms_MY-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ms_MY-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-nb_NO-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-nb_NO-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-nl-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-nl-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-nn_NO-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-nn_NO-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-nr_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-nr_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-nso_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-nso_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-or_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-or_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-pa_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-pa_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-pl_PL-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-pl_PL-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-pt_BR-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-pt_BR-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-pt_PT-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-pt_PT-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ru-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ru-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-sk_SK-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-sk_SK-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-sl_SI-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-sl_SI-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-sr_CS-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-sr_CS-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ss_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ss_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-st_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-st_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-sv-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-sv-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ta_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ta_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-te_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-te_IN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-th_TH-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-th_TH-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-tn_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-tn_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-tr_TR-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-tr_TR-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ts_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ts_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ur-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ur-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-ve_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-ve_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-xh_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-xh_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-zh_CN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-zh_CN-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-zh_TW-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-zh_TW-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-langpack-zu_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-langpack-zu_ZA-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-math-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-math-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-pyuno-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-pyuno-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-testtools-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-testtools-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-writer-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-writer-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openoffice.org-xsltfilter-2.0.4-5.4.17.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openoffice.org-xsltfilter-2.0.4-5.4.17.2")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org / openoffice.org-base / openoffice.org-calc / etc");
  }
}
