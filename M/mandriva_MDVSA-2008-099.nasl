#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:099. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37739);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2008-1096", "CVE-2008-1097");
  script_bugtraq_id(28821, 28822);
  script_xref(name:"MDVSA", value:"2008:099");

  script_name(english:"Mandriva Linux Security Advisory : ImageMagick (MDVSA-2008:099)");
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
"A heap-based buffer overflow vulnerability was found in how
ImageMagick parsed XCF files. If ImageMagick opened a specially
crafted XCF file, it could be made to overwrite heap memory beyond the
bounds of its allocated memory, potentially allowing an attacker to
execute arbitrary code on the system running ImageMagick
(CVE-2008-1096).

Another heap-based buffer overflow vulnerability was found in how
ImageMagick processed certain malformed PCX images. If ImageMagick
opened a specially crafted PCX image file, an attacker could possibly
execute arbitrary code on the system running ImageMagick
(CVE-2008-1097).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ImageMagick-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:imagemagick-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64Magick10.7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64Magick10.7.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64magick10.7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64magick10.7.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libMagick10.7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libMagick10.7.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmagick10.7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmagick10.7.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-Image-Magick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (rpm_check(release:"MDK2007.1", reference:"ImageMagick-6.3.2.9-5.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ImageMagick-desktop-6.3.2.9-5.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ImageMagick-doc-6.3.2.9-5.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64Magick10.7.0-6.3.2.9-5.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"x86_64", reference:"lib64Magick10.7.0-devel-6.3.2.9-5.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libMagick10.7.0-6.3.2.9-5.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libMagick10.7.0-devel-6.3.2.9-5.3mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"perl-Image-Magick-6.3.2.9-5.3mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", reference:"imagemagick-6.3.2.9-10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"imagemagick-desktop-6.3.2.9-10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"imagemagick-doc-6.3.2.9-10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64magick10.7.0-6.3.2.9-10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64magick10.7.0-devel-6.3.2.9-10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libmagick10.7.0-6.3.2.9-10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libmagick10.7.0-devel-6.3.2.9-10.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"perl-Image-Magick-6.3.2.9-10.2mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
