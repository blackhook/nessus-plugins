#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:228. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50581);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2010-3702", "CVE-2010-3704");
  script_xref(name:"MDVSA", value:"2010:228");

  script_name(english:"Mandriva Linux Security Advisory : xpdf (MDVSA-2010:228)");
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
"Multiple vulnerabilities were discovered and corrected in xpdf :

The Gfx::getPos function in the PDF parser in xpdf before 3.02pl5,
allows context-dependent attackers to cause a denial of service
(crash) via unknown vectors that trigger an uninitialized pointer
dereference (CVE-2010-3702).

The FoFiType1::parse function in fofi/FoFiType1.cc in the PDF parser
in xpdf before 3.02pl5, allows context-dependent attackers to cause a
denial of service (crash) and possibly execute arbitrary code via a
PDF file with a crafted Type1 font that contains a negative array
index, which bypasses input validation and which triggers memory
corruption (CVE-2010-3704).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=4
90

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xpdf and / or xpdf-common packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xpdf-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"xpdf-3.02-12.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"xpdf-common-3.02-12.4mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
