#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:031. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14015);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"MDKSA", value:"2003:031-1");

  script_name(english:"Mandrake Linux Security Advisory : usermode (MDKSA-2003:031-1)");
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
"The /usr/bin/shutdown command that comes with the usermode package can
be executed by local users to shutdown all running processes and drop
into a root shell. This command is not really needed to shutdown a
system, so it has been removed and all users are encouraged to
upgrade. Please note that the user must have local console access in
order to obtain a root shell in this fashion.

Update :

The previous updated packages did not properly fix the problem. The
pam files that allow a (physically) local user to shutdown were not
removed. This has been corrected."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected usermode and / or usermode-consoleonly packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:usermode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:usermode-consoleonly");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/03/14");
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
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"usermode-1.42-8.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"usermode-1.44-4.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"usermode-consoleonly-1.44-4.2mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
