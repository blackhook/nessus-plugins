#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:143. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37612);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2008-2927");
  script_xref(name:"MDVSA", value:"2008:143");

  script_name(english:"Mandriva Linux Security Advisory : pidgin (MDVSA-2008:143)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow flaw was found in Pidgin's MSN protocol handler
that could allow for the execution of arbitrary code if a user
received a malicious MSN message (CVE-2008-2927).

In addition, this update provides the ability to use ICQ networks
again on Mandriva Linux 2008.0, as in MDVA-2008:103 (updated pidgin
for 2008.1).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64finch0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64purple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64purple0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfinch0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpurple0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-bonjour");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-facebook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-gevolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-silc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/10");
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
if (rpm_check(release:"MDK2008.0", reference:"finch-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64finch0-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64purple-devel-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64purple0-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libfinch0-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpurple-devel-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libpurple0-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pidgin-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pidgin-bonjour-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pidgin-client-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pidgin-facebook-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pidgin-gevolution-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pidgin-i18n-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pidgin-meanwhile-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pidgin-mono-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pidgin-perl-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pidgin-silc-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"pidgin-tcl-2.2.1-2.1mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", reference:"finch-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64finch0-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64purple-devel-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64purple0-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libfinch0-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libpurple-devel-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libpurple0-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pidgin-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pidgin-bonjour-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pidgin-client-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pidgin-gevolution-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pidgin-i18n-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pidgin-meanwhile-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pidgin-mono-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pidgin-perl-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pidgin-silc-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pidgin-tcl-2.4.1-2.2mdv2008.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
