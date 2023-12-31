#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2000:048. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61839);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2000-0860");
  script_xref(name:"MDKSA", value:"2000:048");

  script_name(english:"Mandrake Linux Security Advisory : mod_php3 (MDKSA-2000:048)");
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
"A problem exists with PHP3 and PHP4 scripts regarding RFC 1867-based
file uploads. PHP saves uploaded files in a temporary directory on the
server, using a temporary name that is referenced as the variable $FOO
where 'FOO' is the name of the file input tag in the submitted form.
Many PHP scripts process $FOO without taking measures to ensure that
it is in fact a file that resides in the temporary directory. Because
of this, it is possible for a remote attacker to supply an arbitrary
file name as the value for $FOO by submitting a standard form input
tag by that name, and thus cause the PHP script to process arbitrary
files. The vulnerability exists in various scripts, and not
necessarily with PHP itself, as the script determines what actions to
perform on the uploaded file. The new versions of both PHP3 and PHP4
make it easier to secure scripts from this particular vulnerability.
They include a new function that makes it easy to determine whether a
certain filename is a temporary uploaded file or not :

/* Text whether a file is an uploaded file or not */
is_uploaded_file($path);

While there is no security vulnerability with PHP3 and PHP4, this
upgrade is offered as a convenience because it includes the above
illustrated method of file testing."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:imap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_php3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_php3-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_php3-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_php3-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_php3-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_php3-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2000/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"imap-4.7-7mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"imap-devel-4.7-7mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"mod_php3-3.0.17RC1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"mod_php3-imap-3.0.17RC1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"mod_php3-manual-3.0.17RC1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"mod_php3-pgsql-3.0.17RC1-1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"mod_php3-3.0.17RC1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"mod_php3-imap-3.0.17RC1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"mod_php3-manual-3.0.17RC1-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"mod_php3-pgsql-3.0.17RC1-1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_php3-3.0.17RC1-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_php3-imap-3.0.17RC1-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_php3-ldap-3.0.17RC1-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_php3-manual-3.0.17RC1-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_php3-mysql-3.0.17RC1-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_php3-pgsql-3.0.17RC1-2mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
