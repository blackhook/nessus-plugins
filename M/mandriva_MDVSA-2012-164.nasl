#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:164. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62504);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2011-1202",
    "CVE-2012-2870",
    "CVE-2012-2871",
    "CVE-2012-2893"
  );
  script_bugtraq_id(
    47668,
    55331,
    55676
  );
  script_xref(name:"MDVSA", value:"2012:164");

  script_name(english:"Mandriva Linux Security Advisory : libxslt (MDVSA-2012:164)");
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
"Multiple vulnerabilities has been discovered and corrected in 
libxslt :

Unspecified vulnerability in XSLT allows remote attackers to obtain
potentially sensitive information about heap memory addresses via
unknown vectors (CVE-2011-1202).

libxslt 1.1.26 and earlier does not properly manage memory, which
might allow remote attackers to cause a denial of service (application
crash) via a crafted XSLT expression that is not properly identified
during XPath navigation, related to (1) the
xsltCompileLocationPathPattern function in libxslt/pattern.c and (2)
the xsltGenerateIdFunction function in libxslt/functions.c
(CVE-2012-2870).

libxml2 2.9.0-rc1 and earlier does not properly support a cast of an
unspecified variable during handling of XSL transforms, which allows
remote attackers to cause a denial of service or possibly have unknown
other impact via a crafted document, related to the _xmlNs data
structure in include/libxml/tree.h (CVE-2012-2871).

Double free vulnerability in libxslt allows remote attackers to cause
a denial of service or possibly have unspecified other impact via
vectors related to XSL transforms (CVE-2012-2893).

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xslt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxslt1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-libxslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xsltproc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/12");
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
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64xslt-devel-1.1.26-4.3-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64xslt1-1.1.26-4.3-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libxslt-devel-1.1.26-4.3-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libxslt1-1.1.26-4.3-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"python-libxslt-1.1.26-4.3-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"xsltproc-1.1.26-4.3-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
