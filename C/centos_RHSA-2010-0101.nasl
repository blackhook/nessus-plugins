#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0101 and 
# CentOS Errata and Security Advisory 2010:0101 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44598);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302");
  script_bugtraq_id(38218);
  script_xref(name:"RHSA", value:"2010:0101");

  script_name(english:"CentOS 3 / 4 / 5 : openoffice.org (CESA-2010:0101)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openoffice.org packages that correct multiple security issues
are now available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

OpenOffice.org is an office productivity suite that includes desktop
applications, such as a word processor, spreadsheet application,
presentation manager, formula editor, and a drawing program.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way OpenOffice.org parsed XPM files. An attacker could
create a specially crafted document, which once opened by a local,
unsuspecting user, could lead to arbitrary code execution with the
permissions of the user running OpenOffice.org. Note: This flaw
affects embedded XPM files in OpenOffice.org documents as well as
stand-alone XPM files. (CVE-2009-2949)

An integer underflow flaw and a boundary error flaw, both possibly
leading to a heap-based buffer overflow, were found in the way
OpenOffice.org parsed certain records in Microsoft Word documents. An
attacker could create a specially crafted Microsoft Word document,
which once opened by a local, unsuspecting user, could cause
OpenOffice.org to crash or, potentially, execute arbitrary code with
the permissions of the user running OpenOffice.org. (CVE-2009-3301,
CVE-2009-3302)

A heap-based buffer overflow flaw, leading to memory corruption, was
found in the way OpenOffice.org parsed GIF files. An attacker could
create a specially crafted document, which once opened by a local,
unsuspecting user, could cause OpenOffice.org to crash. Note: This
flaw affects embedded GIF files in OpenOffice.org documents as well as
stand-alone GIF files. (CVE-2009-2950)

All users of OpenOffice.org are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running instances of OpenOffice.org applications must be restarted
for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-February/016497.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f08d475e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-February/016498.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6cb82ae5"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-February/016499.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f09209c9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-February/016500.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4678357"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-February/016503.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39a00bda"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-February/016504.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a47bf970"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openoffice.org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-as_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-kn_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ml_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-mr_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nr_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-nso_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-or_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ss_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-st_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-te_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-tn_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ts_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-ve_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-xh_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-sdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-graphicfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-javafilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-af_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-bg_BG");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ca_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-cs_CZ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-cy_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-da_DK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-el_GR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-et_EE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-eu_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-fi_FI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ga_IE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-gl_ES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-gu_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-he_IL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-hi_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-hr_HR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-hu_HU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ja_JP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ko_KR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-lt_LT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ms_MY");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-nb_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-nn_NO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-pa_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-pl_PL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-pt_PT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-sk_SK");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-sl_SI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-sr_CS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-ta_IN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-th_TH");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-tr_TR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-langpack-zu_ZA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-testtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openoffice.org2-xsltfilter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-1.1.2-46.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-1.1.2-46.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-i18n-1.1.2-46.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-i18n-1.1.2-46.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"openoffice.org-libs-1.1.2-46.2.0.EL3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"openoffice.org-libs-1.1.2-46.2.0.EL3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-i18n-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-i18n-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-kde-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org-libs-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org-libs-1.1.5-10.6.0.7.EL4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-base-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-base-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-calc-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-calc-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-core-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-core-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-debuginfo-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-debuginfo-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-draw-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-draw-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-emailmerge-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-emailmerge-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-graphicfilter-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-graphicfilter-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-impress-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-impress-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-javafilter-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-javafilter-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-af_ZA-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-af_ZA-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ar-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ar-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-bg_BG-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-bg_BG-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-bn-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-bn-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ca_ES-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ca_ES-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-cs_CZ-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-cs_CZ-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-cy_GB-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-cy_GB-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-da_DK-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-da_DK-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-de-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-de-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-el_GR-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-el_GR-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-es-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-es-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-et_EE-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-et_EE-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-eu_ES-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-eu_ES-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-fi_FI-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-fi_FI-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-fr-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-fr-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ga_IE-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ga_IE-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-gl_ES-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-gl_ES-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-gu_IN-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-gu_IN-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-he_IL-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-he_IL-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-hi_IN-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-hi_IN-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-hr_HR-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-hr_HR-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-hu_HU-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-hu_HU-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-it-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-it-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ja_JP-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ja_JP-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ko_KR-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ko_KR-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-lt_LT-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-lt_LT-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ms_MY-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ms_MY-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-nb_NO-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-nb_NO-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-nl-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-nl-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-nn_NO-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-nn_NO-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-pa_IN-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-pa_IN-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-pl_PL-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-pl_PL-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-pt_BR-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-pt_BR-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-pt_PT-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-pt_PT-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ru-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ru-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-sk_SK-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-sk_SK-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-sl_SI-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-sl_SI-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-sr_CS-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-sr_CS-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-sv-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-sv-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-ta_IN-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-ta_IN-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-th_TH-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-th_TH-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-tr_TR-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-tr_TR-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-zh_CN-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-zh_CN-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-zh_TW-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-zh_TW-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-langpack-zu_ZA-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-langpack-zu_ZA-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-math-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-math-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-pyuno-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-pyuno-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-testtools-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-testtools-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-writer-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-writer-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"openoffice.org2-xsltfilter-2.0.4-5.7.0.6.1.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"openoffice.org2-xsltfilter-2.0.4-5.7.0.6.1.el4_8.3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"openoffice.org-base-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-calc-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-core-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-draw-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-emailmerge-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-graphicfilter-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-headless-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-impress-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-javafilter-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-af_ZA-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ar-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-as_IN-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-bg_BG-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-bn-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ca_ES-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-cs_CZ-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-cy_GB-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-da_DK-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-de-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-el_GR-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-es-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-et_EE-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-eu_ES-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-fi_FI-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-fr-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ga_IE-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-gl_ES-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-gu_IN-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-he_IL-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hi_IN-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hr_HR-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-hu_HU-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-it-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ja_JP-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-kn_IN-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ko_KR-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-lt_LT-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ml_IN-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-mr_IN-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ms_MY-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nb_NO-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nl-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nn_NO-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nr_ZA-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-nso_ZA-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-or_IN-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pa_IN-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pl_PL-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pt_BR-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-pt_PT-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ru-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sk_SK-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sl_SI-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sr_CS-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ss_ZA-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-st_ZA-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-sv-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ta_IN-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-te_IN-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-th_TH-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-tn_ZA-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-tr_TR-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ts_ZA-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ur-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-ve_ZA-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-xh_ZA-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zh_CN-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zh_TW-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-langpack-zu_ZA-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-math-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-pyuno-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-sdk-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-sdk-doc-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-testtools-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-writer-2.3.0-6.11.el5_4.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"openoffice.org-xsltfilter-2.3.0-6.11.el5_4.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org / openoffice.org-base / openoffice.org-calc / etc");
}
