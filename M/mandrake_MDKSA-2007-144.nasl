#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:144. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25697);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-0245");
  script_bugtraq_id(24450);
  script_xref(name:"MDKSA", value:"2007:144");

  script_name(english:"Mandrake Linux Security Advisory : openoffice.org (MDKSA-2007:144)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap overflow flaw was found in the RTF import filter of
OpenOffice.org. If a victim were to open a specially crafted RTF file,
OpenOffice.org could crash or possibly execute arbitrary code.

Updated packages have been patched to prevent the above issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-galleries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-mimelnk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org-ooqstart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-galleries");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-en_GB");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-pt_BR");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-zh_CN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-zh_TW");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openoffice.org64-ooqstart");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-devel-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-devel-doc-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-galleries-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-gnome-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-kde-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-af-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-ar-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-bg-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-br-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-bs-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-ca-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-cs-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-cy-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-da-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-de-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-el-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-en_GB-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-es-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-et-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-eu-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-fi-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-fr-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-he-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-hi-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-hu-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-it-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-ja-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-ko-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-mk-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-nb-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-nl-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-nn-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-pl-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-pt-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-pt_BR-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-ru-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-sk-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-sl-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-sv-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-ta-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-tr-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-zh_CN-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-zh_TW-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-l10n-zu-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-mimelnk-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-mono-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"openoffice.org-ooqstart-2.0.4-2.5mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-devel-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-devel-doc-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-galleries-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-gnome-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-kde-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-af-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-ar-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-bg-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-br-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-bs-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-ca-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-cs-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-cy-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-da-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-de-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-el-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-en_GB-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-es-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-et-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-eu-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-fi-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-fr-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-he-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-hi-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-hu-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-it-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-ja-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-ko-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-mk-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-nb-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-nl-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-nn-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-pl-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-pt-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-pt_BR-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-ru-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-sk-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-sl-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-sv-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-ta-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-tr-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-zh_CN-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-zh_TW-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-l10n-zu-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-mono-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"openoffice.org-ooqstart-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-devel-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-devel-doc-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-galleries-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-gnome-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-kde-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-af-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-ar-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-bg-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-br-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-bs-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-ca-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-cs-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-cy-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-da-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-de-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-el-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-en_GB-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-es-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-et-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-eu-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-fi-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-fr-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-he-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-hi-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-hu-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-it-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-ja-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-ko-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-mk-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-nb-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-nl-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-nn-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-pl-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-pt-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-pt_BR-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-ru-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-sk-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-sl-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-sv-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-ta-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-tr-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-zh_CN-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-zh_TW-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-l10n-zu-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-mono-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"openoffice.org64-ooqstart-2.1.0-10.1mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
