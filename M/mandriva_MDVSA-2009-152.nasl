#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:152. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39871);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2009-1894");
  script_xref(name:"MDVSA", value:"2009:152");

  script_name(english:"Mandriva Linux Security Advisory : pulseaudio (MDVSA-2009:152)");
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
"A vulnerability has been found and corrected in pulseaudio :

Tavis Ormandy and Julien Tinnes of the Google Security Team discovered
that pulseaudio, when installed setuid root, does not drop privileges
before re-executing itself to achieve immediate bindings. This can be
exploited by a user who has write access to any directory on the file
system containing /usr/bin to gain local root access. The user needs
to exploit a race condition related to creating a hard link
(CVE-2009-1894).

This update provides fixes for this vulnerability."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pulseaudio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pulseaudio0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pulsecore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pulseglib20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pulsezeroconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpulseaudio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpulseaudio0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpulsecore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpulseglib20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpulsezeroconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pulseaudio-esound-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pulseaudio-module-bluetooth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pulseaudio-module-gconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pulseaudio-module-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pulseaudio-module-lirc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pulseaudio-module-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pulseaudio-module-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pulseaudio-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/20");
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
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64pulseaudio-devel-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64pulseaudio0-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64pulsecore5-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64pulseglib20-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"x86_64", reference:"lib64pulsezeroconf0-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libpulseaudio-devel-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libpulseaudio0-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libpulsecore5-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libpulseglib20-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"libpulsezeroconf0-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pulseaudio-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pulseaudio-esound-compat-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pulseaudio-module-bluetooth-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pulseaudio-module-gconf-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pulseaudio-module-jack-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pulseaudio-module-lirc-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pulseaudio-module-x11-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pulseaudio-module-zeroconf-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"pulseaudio-utils-0.9.9-7.3mdv2008.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64pulseaudio-devel-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64pulseaudio0-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64pulsecore5-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64pulseglib20-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64pulsezeroconf0-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpulseaudio-devel-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpulseaudio0-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpulsecore5-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpulseglib20-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpulsezeroconf0-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pulseaudio-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pulseaudio-esound-compat-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pulseaudio-module-bluetooth-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pulseaudio-module-gconf-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pulseaudio-module-jack-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pulseaudio-module-lirc-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pulseaudio-module-x11-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pulseaudio-module-zeroconf-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pulseaudio-utils-0.9.10-11.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64pulseaudio-devel-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64pulseaudio0-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64pulseglib20-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64pulsezeroconf0-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libpulseaudio-devel-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libpulseaudio0-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libpulseglib20-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libpulsezeroconf0-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pulseaudio-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pulseaudio-esound-compat-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pulseaudio-module-bluetooth-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pulseaudio-module-gconf-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pulseaudio-module-jack-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pulseaudio-module-lirc-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pulseaudio-module-x11-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pulseaudio-module-zeroconf-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pulseaudio-utils-0.9.15-2.0.6mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
