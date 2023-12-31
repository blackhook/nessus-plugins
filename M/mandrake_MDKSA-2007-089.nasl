#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:089. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25113);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2007-1001", "CVE-2007-1285", "CVE-2007-1583", "CVE-2007-1717", "CVE-2007-1718", "CVE-2007-1887");
  script_bugtraq_id(22764, 23016, 23145, 23357);
  script_xref(name:"MDKSA", value:"2007:089");

  script_name(english:"Mandrake Linux Security Advisory : php (MDKSA-2007:089)");
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
"A heap-based buffer overflow vulnerability was found in PHP's gd
extension. A script that could be forced to process WBMP images from
an untrusted source could result in arbitrary code execution
(CVE-2007-1001).

A DoS flaw was found in how PHP processed a deeply nested array. A
remote attacker could cause the PHP intrerpreter to creash by
submitting an input variable with a deeply nested array
(CVE-2007-1285).

A vulnerability in the way the mbstring extension set global variables
was discovered where a script using the mb_parse_str() function to set
global variables could be forced to to enable the register_globals
configuration option, possibly resulting in global variable injection
(CVE-2007-1583).

A vulnerability in how PHP's mail() function processed header data was
discovered. If a script sent mail using a subject header containing a
string from an untrusted source, a remote attacker could send bulk
email to unintended recipients (CVE-2007-1718).

A buffer overflow in the sqlite_decode_function() in the bundled
sqlite library could allow context-dependent attackers to execute
arbitrary code (CVE-2007-1887).

Updated packages have been patched to correct these issues. Also note
that the default use of the Hardened PHP patch helped to protect
against some of these issues prior to patching."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64php5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libphp5_common5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-fcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"MDK2007.0", cpu:"x86_64", reference:"lib64php5_common5-5.1.6-1.7mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libphp5_common5-5.1.6-1.7mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-cgi-5.1.6-1.7mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-cli-5.1.6-1.7mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-devel-5.1.6-1.7mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-fcgi-5.1.6-1.7mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-gd-5.1.6-1.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-mbstring-5.1.6-1.1mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"php-sqlite-5.1.6-1.1mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
