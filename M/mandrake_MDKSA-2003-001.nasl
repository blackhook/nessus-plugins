#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:001. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(13986);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2002-1366", "CVE-2002-1367", "CVE-2002-1368", "CVE-2002-1369", "CVE-2002-1371", "CVE-2002-1372", "CVE-2002-1383", "CVE-2002-1384");
  script_xref(name:"MDKSA", value:"2003:001");

  script_name(english:"Mandrake Linux Security Advisory : cups (MDKSA-2003:001)");
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
"iDefense reported several security problems in CUPS that can lead to
local and remote root compromise. An integer overflow in the HTTP
interface can be used to gain remote access with CUPS privilege. A
local file race condition can be used to gain root privilege, although
the previous bug must be exploited first. An attacker can remotely add
printers to the vulnerable system. A remote DoS can be accomplished
due to negative length in the memcpy() call. An integer overflow in
image handling code can be used to gain higher privilege. An attacker
can gain local root privilege due to a buffer overflow of the
'options' buffer. A design problem can be exploited to gain local root
access, however this needs an added printer (which can also be done,
as per a previously noted bug). Wrong handling of zero-width images
can be abused to gain higher privilege. Finally, a file descriptor
leak and DoS due to missing checks of return values of file/socket
operations.

MandrakeSoft recommends all users upgrade these CUPS packages
immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.idefense.com/advisory/12.23.02.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cups-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcups1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcups1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:printer-testpages");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/09");
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
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"cups-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"cups-devel-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"cups-serial-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"printer-testpages-1.1.18-1.4mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"cups-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"cups-common-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"cups-serial-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"libcups1-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"libcups1-devel-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"printer-testpages-1.1.18-1.4mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"cups-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"cups-common-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"cups-serial-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libcups1-1.1.18-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libcups1-devel-1.1.18-1.4mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"cups-1.1.18-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"cups-common-1.1.18-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"cups-serial-1.1.18-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libcups1-1.1.18-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libcups1-devel-1.1.18-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"cups-1.1.18-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"cups-common-1.1.18-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"cups-serial-1.1.18-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libcups1-1.1.18-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libcups1-devel-1.1.18-1.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
