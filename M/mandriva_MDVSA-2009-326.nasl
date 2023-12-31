#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:326. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43045);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2008-3963",
    "CVE-2008-4098",
    "CVE-2008-4456",
    "CVE-2009-2446"
  );
  script_bugtraq_id(
    29106,
    31081,
    31486,
    35609
  );
  script_xref(name:"MDVSA", value:"2009:326");

  script_name(english:"Mandriva Linux Security Advisory : mysql (MDVSA-2009:326)");
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
"Multiple vulnerabilities has been found and corrected in mysql :

MySQL 5.0 before 5.0.66, 5.1 before 5.1.26, and 6.0 before 6.0.6 does
not properly handle a b'' (b single-quote single-quote) token, aka an
empty bit-string literal, which allows remote attackers to cause a
denial of service (daemon crash) by using this token in a SQL
statement (CVE-2008-3963).

MySQL before 5.0.67 allows local users to bypass certain privilege
checks by calling CREATE TABLE on a MyISAM table with modified (1)
DATA DIRECTORY or (2) INDEX DIRECTORY arguments that are originally
associated with pathnames without symlinks, and that can point to
tables created at a future time at which a pathname is modified to
contain a symlink to a subdirectory of the MySQL home data directory.
NOTE: this vulnerability exists because of an incomplete fix for
CVE-2008-4097 (CVE-2008-4098).

Cross-site scripting (XSS) vulnerability in the command-line client in
MySQL 5.0.26 through 5.0.45, when the --html option is enabled, allows
attackers to inject arbitrary web script or HTML by placing it in a
database cell, which might be accessed by this client when composing
an HTML document (CVE-2008-4456).

Multiple format string vulnerabilities in the dispatch_command
function in libmysqld/sql_parse.cc in mysqld in MySQL 4.0.0 through
5.0.83 allow remote authenticated users to cause a denial of service
(daemon crash) and possibly have unspecified other impact via format
string specifiers in a database name in a (1) COM_CREATE_DB or (2)
COM_DROP_DB request. NOTE: some of these details are obtained from
third-party information (CVE-2009-2446).

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers

This update provides fixes for this vulnerability."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79, 134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mysql15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmysql15");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-max");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-management");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-ndb-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/08");
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
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64mysql-devel-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64mysql-static-devel-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64mysql15-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libmysql-devel-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libmysql-static-devel-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libmysql15-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mysql-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mysql-bench-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mysql-client-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mysql-common-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mysql-max-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mysql-ndb-extra-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mysql-ndb-management-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mysql-ndb-storage-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mysql-ndb-tools-5.0.45-8.3mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
