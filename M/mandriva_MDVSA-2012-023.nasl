#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:023. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58103);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2012-0823");
  script_bugtraq_id(51775, 52107);
  script_xref(name:"MDVSA", value:"2012:023-1");

  script_name(english:"Mandriva Linux Security Advisory : libvpx (MDVSA-2012:023-1)");
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
"A vulnerability has been found and corrected in libvpx :

VP8 Codec SDK (libvpx) before 1.0.0 Duclair allows remote attackers to
cause a denial of service (application crash) via (1) unspecified
corrupt input or (2) by starting decoding from a P-frame, which
triggers an out-of-bounds read, related to the clamping of motion
vectors in SPLITMV blocks (CVE-2012-0823).

The updated packages have been patched to correct this issue.

Update :

This is a symbolic advisory correction because there was a clash with
MDVSA-2012:023 that addressed libxml2."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64vpx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64vpx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libvpx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libvpx-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libvpx0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/23");
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
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64vpx-devel-0.9.7-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64vpx0-0.9.7-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libvpx-devel-0.9.7-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"libvpx-utils-0.9.7-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libvpx0-0.9.7-0.2mdv2010.2", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64vpx-devel-0.9.7-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64vpx0-0.9.7-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libvpx-devel-0.9.7-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"libvpx-utils-0.9.7-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libvpx0-0.9.7-0.2-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
