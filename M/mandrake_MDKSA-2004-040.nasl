#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:040. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14139);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2004-0421");
  script_xref(name:"MDKSA", value:"2004:040");

  script_name(english:"Mandrake Linux Security Advisory : libpng (MDKSA-2004:040)");
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
"Steve Grubb discovered that libpng would access memory that is out of
bounds when creating an error message. The impact of this bug is not
clear, but it could lead to a core dump in a program using libpng, or
could result in a DoS (Denial of Service) condition in a daemon that
uses libpng to process PNG imagaes.

The updated packages are patched to correct the vulnerability."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64png3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64png3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64png3-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpng3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpng3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpng3-static-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64png3-1.2.5-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64png3-devel-1.2.5-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64png3-static-devel-1.2.5-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libpng3-1.2.5-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libpng3-devel-1.2.5-10.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libpng3-static-devel-1.2.5-10.2.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libpng3-1.2.5-2.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libpng3-devel-1.2.5-2.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"libpng3-static-devel-1.2.5-2.2.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64png3-1.2.5-7.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64png3-devel-1.2.5-7.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64png3-static-devel-1.2.5-7.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libpng3-1.2.5-7.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libpng3-devel-1.2.5-7.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libpng3-static-devel-1.2.5-7.2.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
