#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:121. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22042);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2006-2200");
  script_xref(name:"MDKSA", value:"2006:121");

  script_name(english:"Mandrake Linux Security Advisory : xine-lib (MDKSA-2006:121)");
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
"Stack-based buffer overflow in MiMMS 0.0.9 allows remote attackers to
cause a denial of service (application crash) and possibly execute
arbitrary code via the (1) send_command, (2) string_utf16, (3)
get_data, and (4) get_media_packet functions, and possibly other
functions. Xine-lib contains an embedded copy of the same vulnerable
code.

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xine1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xine1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxine1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxine1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-dxr3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-esd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-polyp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xine-smb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64xine1-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"x86_64", reference:"lib64xine1-devel-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libxine1-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", cpu:"i386", reference:"libxine1-devel-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-aa-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-arts-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-dxr3-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-esd-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-flac-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-gnomevfs-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-image-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-plugins-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-polyp-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"xine-smb-1.1.0-9.6.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
