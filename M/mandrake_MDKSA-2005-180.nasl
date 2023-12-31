#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:180. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20040);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-2967");
  script_xref(name:"MDKSA", value:"2005:180");

  script_name(english:"Mandrake Linux Security Advisory : xine-lib (MDKSA-2005:180)");
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
"When playing an Audio CD, a xine-lib based media application contacts
a CDDB server to retrieve metadata like the title and artist's name.
During processing of this data, a response from the server, which is
located in memory on the stack, is passed to the fprintf() function as
a format string. An attacker can set up a malicious CDDB server and
trick the client into using this server instead of the pre- configured
one. Alternatively, any user and therefore the attacker can modify
entries in the official CDDB server. Using this format string
vulnerability, attacker-chosen data can be written to an
attacker-chosen memory location. This allows the attacker to alter the
control flow and to execute malicious code with the permissions of the
user running the application.

This problem was reported by Ulf Harnhammar from the Debian Security
Audit Project.

The updated packages have been patched to correct this problem."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xine1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xine1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxine1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxine1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-dxr3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-esd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-polyp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-smb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
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
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64xine1-1-0.rc5.9.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64xine1-devel-1-0.rc5.9.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libxine1-1-0.rc5.9.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libxine1-devel-1-0.rc5.9.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xine-aa-1-0.rc5.9.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xine-arts-1-0.rc5.9.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xine-dxr3-1-0.rc5.9.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xine-esd-1-0.rc5.9.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xine-flac-1-0.rc5.9.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xine-gnomevfs-1-0.rc5.9.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xine-plugins-1-0.rc5.9.3.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64xine1-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64xine1-devel-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libxine1-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libxine1-devel-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xine-aa-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xine-arts-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xine-dxr3-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xine-esd-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xine-flac-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xine-gnomevfs-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xine-plugins-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xine-polyp-1.0-8.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xine-smb-1.0-8.2.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64xine1-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64xine1-devel-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libxine1-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libxine1-devel-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-aa-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-arts-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-dxr3-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-esd-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-flac-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-gnomevfs-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-image-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-plugins-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-polyp-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-smb-1.1.0-8.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
