#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:222. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37295);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_bugtraq_id(26367);
  script_xref(name:"MDKSA", value:"2007:222");

  script_name(english:"Mandrake Linux Security Advisory : koffice (MDKSA-2007:222)");
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
"Alin Rad Pop found several flaws in how PDF files are handled in
koffice. An attacker could create a malicious PDF file that would
cause koffice to crash or potentially execute arbitrary code when
opened.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kivio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-koshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kplato");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:koffice-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-karbon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kexi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kformula-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kivio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kivio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-koshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kplato");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kpresenter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-krita-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kspread-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kugar-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-kword-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64koffice2-progs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-karbon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-karbon-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kexi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kexi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kformula");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kformula-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kivio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kivio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-koshell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kplato");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kpresenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kpresenter-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-krita");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-krita-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kspread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kspread-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kugar-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kword");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-kword-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkoffice2-progs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.1", reference:"koffice-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-karbon-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-kexi-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-kformula-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-kivio-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-koshell-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-kplato-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-kpresenter-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-krita-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-kspread-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-kugar-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-kword-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"koffice-progs-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-karbon-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-karbon-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kexi-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kexi-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kformula-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kformula-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kivio-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kivio-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-koshell-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kplato-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kpresenter-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kpresenter-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-krita-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-krita-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kspread-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kspread-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kugar-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kugar-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kword-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-kword-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-progs-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64koffice2-progs-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-karbon-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-karbon-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kexi-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kexi-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kformula-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kformula-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kivio-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kivio-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-koshell-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kplato-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kpresenter-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kpresenter-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-krita-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-krita-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kspread-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kspread-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kugar-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kugar-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kword-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-kword-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-progs-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libkoffice2-progs-devel-1.6.2-2.2mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", reference:"koffice-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-karbon-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-kexi-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-kformula-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-kivio-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-koshell-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-kplato-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-kpresenter-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-krita-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-kspread-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-kugar-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-kword-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"koffice-progs-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-karbon-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-karbon-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kexi-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kexi-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kformula-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kformula-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kivio-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kivio-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-koshell-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kplato-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kpresenter-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kpresenter-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-krita-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-krita-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kspread-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kspread-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kugar-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kugar-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kword-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-kword-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-progs-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64koffice2-progs-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-karbon-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-karbon-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kexi-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kexi-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kformula-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kformula-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kivio-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kivio-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-koshell-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kplato-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kpresenter-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kpresenter-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-krita-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-krita-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kspread-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kspread-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kugar-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kugar-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kword-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-kword-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-progs-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libkoffice2-progs-devel-1.6.3-9.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
