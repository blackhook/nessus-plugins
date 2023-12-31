#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2000:027. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(61824);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_xref(name:"MDKSA", value:"2000:027-1");

  script_name(english:"Mandrake Linux Security Advisory : netscape (MDKSA-2000:027-1)");
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
"Previous versions of Netscape, from version 3.0 to 4.73 contain a
serious overflow flaw due to improper input verification in Netscape's
JPEG processing code. The way Netscape processed JPEG comments trusted
the length parameter for comment fields. By manipulating this value,
it was possible to cause Netscape to read in an excessive amount of
data which would then overwrite memory. Data with a malicious design
could allow a remote site to execute arbitrary code as the user of
Netscape on the client system. It is highly recommended that everyone
using Netscape upgrade to this latest version that fixes the flaw.

Update :

The md5sums listed in the previous advisory are no longer valid. We
are using the same RPM packages for 6.0, 6.1, and 7.0 so the md5ums
have changed. The package for 7.1 has also been updated to incorporate
many of the enhancements used in Linux-Mandrake 7.1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-castellano");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-catalan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-communicator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-euskara");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-francais");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-navigator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netscape-walon");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2000/08/01");
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
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"netscape-common-4.74-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"netscape-communicator-4.74-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"netscape-navigator-4.74-2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"netscape-common-4.74-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"netscape-communicator-4.74-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"netscape-navigator-4.74-2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.0", reference:"netscape-castellano-4.74-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"netscape-common-4.74-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"netscape-communicator-4.74-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", reference:"netscape-francais-4.74-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", cpu:"i386", reference:"netscape-navigator-4.74-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.0", reference:"netscape-walon-4.74-1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.1", reference:"netscape-castellano-4.74-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", reference:"netscape-catalan-4.74-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"netscape-common-4.74-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"netscape-communicator-4.74-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", reference:"netscape-euskara-4.74-1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", reference:"netscape-francais-4.74-2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"netscape-navigator-4.74-3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", reference:"netscape-walon-4.74-1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
