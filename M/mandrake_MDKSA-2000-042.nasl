#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2000:042. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61835);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"MDKSA", value:"2000:042");

  script_name(english:"Mandrake Linux Security Advisory : mgetty (MDKSA-2000:042)");
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
"There is a problem in the mgetty package, which contains a number of
tools for sending and receiving faxes. The faxrunq tool uses a marker
file in the /tmp directory, which is world-writable, in an insecure
fashion. This problem, if exploited, allows malicious users to
overwrite files on the system via a symlink attack which are owned by
the user that is invoking faxrunq. All versions of mgetty prior to
1.1.22 are vulnerable."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mgetty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mgetty-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mgetty-sendfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mgetty-viewfax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mgetty-voice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2000/08/31");
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
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"mgetty-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"mgetty-contrib-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"mgetty-sendfax-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"mgetty-viewfax-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"mgetty-voice-1.1.22-2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"mgetty-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"mgetty-contrib-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"mgetty-sendfax-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"mgetty-viewfax-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"mgetty-voice-1.1.22-2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"mgetty-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"mgetty-contrib-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"mgetty-sendfax-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"mgetty-viewfax-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"mgetty-voice-1.1.22-2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mgetty-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mgetty-contrib-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mgetty-sendfax-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mgetty-viewfax-1.1.22-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mgetty-voice-1.1.22-2mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
