#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:052. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58585);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2012-0444");
  script_bugtraq_id(51753);
  script_xref(name:"MDVSA", value:"2012:052");

  script_name(english:"Mandriva Linux Security Advisory : libvorbis (MDVSA-2012:052)");
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
"A vulnerability has been found and corrected in libvorbis :

If a specially crafted Ogg Vorbis media file was opened by an
application using libvorbis, it could cause the application to crash
or, possibly, execute arbitrary code with the privileges of the user
running the application (CVE-2012-0444).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=786026"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64vorbis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64vorbis0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64vorbisenc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64vorbisfile3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libvorbis-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libvorbis0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libvorbisenc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libvorbisfile3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/04");
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
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64vorbis-devel-1.3.1-1.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64vorbis0-1.3.1-1.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64vorbisenc2-1.3.1-1.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64vorbisfile3-1.3.1-1.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libvorbis-devel-1.3.1-1.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libvorbis0-1.3.1-1.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libvorbisenc2-1.3.1-1.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libvorbisfile3-1.3.1-1.1mdv2010.2", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64vorbis-devel-1.3.2-2.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64vorbis0-1.3.2-2.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64vorbisenc2-1.3.2-2.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64vorbisfile3-1.3.2-2.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libvorbis-devel-1.3.2-2.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libvorbis0-1.3.2-2.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libvorbisenc2-1.3.2-2.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libvorbisfile3-1.3.2-2.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
