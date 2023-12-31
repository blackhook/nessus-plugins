#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:022. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24637);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-0103", "CVE-2007-0104");
  script_xref(name:"MDKSA", value:"2007:022");

  script_name(english:"Mandrake Linux Security Advisory : tetex (MDKSA-2007:022)");
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
"The Adobe PDF specification 1.3, as implemented by xpdf 3.0.1 patch 2,
kpdf in KDE before 3.5.5, and other products, allows remote attackers
to have an unknown impact, possibly including denial of service
(infinite loop), arbitrary code execution, or memory corruption, via a
PDF file with a (1) crafted catalog dictionary or (2) a crafted Pages
attribute that references an invalid page tree node.

The updated packages have been patched to correct this problem."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:jadetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvilj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvipdfm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-mfwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-texi2html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xmltex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"jadetex-3.12-110.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-afm-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-context-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-devel-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-doc-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-dvilj-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-dvipdfm-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-dvips-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-latex-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-mfwin-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-texi2html-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"tetex-xdvi-3.0-12.3.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xmltex-1.9-58.3.20060mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2007.0", reference:"jadetex-3.12-116.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-afm-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-context-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-devel-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-doc-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-dvilj-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-dvipdfm-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-dvips-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-latex-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-mfwin-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-texi2html-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"tetex-xdvi-3.0-18.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"xmltex-1.9-64.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
