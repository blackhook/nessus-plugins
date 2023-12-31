#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:085. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14067);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2003-0547", "CVE-2003-0548", "CVE-2003-0549");
  script_xref(name:"MDKSA", value:"2003:085");

  script_name(english:"Mandrake Linux Security Advisory : gdm (MDKSA-2003:085)");
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
"Several vulnerabilities were discovered in versions of gdm prior to
2.4.1.6. The first vulnerability is that any user can read any text
file on the system due to code originally written to be run as the
user logging in was in fact being run as the root user. This code is
what allows the examination of the ~/.xsession-errors file. If a user
makes a symlink from this file to any other file on the system during
the session and ensures that the session lasts less than ten seconds,
the user can read the file provided it was readable as a text file.

Another two vulnerabilities were found in the XDMCP code that could be
exploited to crash the main gdm daemon which would inhibit starting
any new sessions (although the current session would be unaffected).
The first problem here is due to the indirect query structure being
used right after being freed due to a missing 'continue' statement in
a loop; this happens if a choice of server expired and the client
tried to connect.

The second XDMCP problem is that when authorization data is being
checked as a string, the length is not checked first. If the data is
less than 18 bytes long, the daemon may wander off the end of the
string a few bytes in the strncmp which could cause a SEGV.

These updated packages bring gdm to version 2.4.1.6 which is not
vulnerable to any of these problems. Also note that XDMCP support is
disabled by default in gdm."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdm and / or gdm-Xnest packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gdm-Xnest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/08/21");
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
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"gdm-2.4.1.6-0.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"gdm-Xnest-2.4.1.6-0.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"gdm-2.4.1.6-0.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"gdm-Xnest-2.4.1.6-0.3mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
