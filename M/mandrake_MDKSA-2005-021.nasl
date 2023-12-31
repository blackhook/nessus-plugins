#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:021. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16258);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-0064");
  script_xref(name:"MDKSA", value:"2005:021");

  script_name(english:"Mandrake Linux Security Advisory : tetex (MDKSA-2005:021)");
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
"A buffer overflow vulnerability was discovered in the xpdf PDF code,
which could allow for arbitrary code execution as the user viewing a
PDF file. The vulnerability exists due to insufficient bounds checking
while processing a PDF file that provides malicious values in the
/Encrypt /Length tag. Tetex uses xpdf code and is susceptible to the
same vulnerability.

The updated packages have been patched to prevent these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"jadetex-3.12-93.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-afm-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-context-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-devel-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-doc-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-dvilj-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-dvipdfm-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-dvips-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-latex-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-mfwin-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-texi2html-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"tetex-xdvi-2.0.2-14.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"xmltex-1.9-41.2.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"jadetex-3.12-98.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-afm-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-context-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-devel-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-doc-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-dvilj-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-dvipdfm-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-dvips-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-latex-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-mfwin-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-texi2html-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"tetex-xdvi-2.0.2-19.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xmltex-1.9-46.2.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
