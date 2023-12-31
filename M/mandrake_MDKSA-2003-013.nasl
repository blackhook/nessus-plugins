#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:013. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(13998);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2003-0073");
  script_xref(name:"MDKSA", value:"2003:013");

  script_name(english:"Mandrake Linux Security Advisory : MYSQL (MDKSA-2003:013)");
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
"Aleksander Adamowski informed MandrakeSoft that the MySQL developers
fixed a DoS vulnerability in the recently released 3.23.55 version of
MySQL. A double free() pointer bug in the mysql_change_user() handling
would allow a specially hacked mysql client to crash the main mysqld
server. This vulnerability can only be exploited by first logging in
with a valid user account."
  );
  # http://www.mysql.com/doc/en/News-3.23.55.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/refman/4.1/en/news-3-23-55.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-Max");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:MySQL-shared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql10-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/03");
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
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"MySQL-3.23.31-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"MySQL-bench-3.23.31-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"MySQL-client-3.23.31-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"MySQL-devel-3.23.31-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"MySQL-shared-3.23.31-1.4mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"MySQL-3.23.36-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"MySQL-bench-3.23.36-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"MySQL-client-3.23.36-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"MySQL-devel-3.23.36-2.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"MySQL-shared-3.23.36-2.3mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"MySQL-3.23.41-5.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"MySQL-bench-3.23.41-5.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"MySQL-client-3.23.41-5.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"MySQL-devel-3.23.41-5.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"MySQL-shared-3.23.41-5.3mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"MySQL-3.23.47-5.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"MySQL-bench-3.23.47-5.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"MySQL-client-3.23.47-5.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libmysql10-3.23.47-5.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"libmysql10-devel-3.23.47-5.3mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"MySQL-3.23.52-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"MySQL-Max-3.23.52-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"MySQL-bench-3.23.52-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"MySQL-client-3.23.52-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libmysql10-3.23.52-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"libmysql10-devel-3.23.52-1.3mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
