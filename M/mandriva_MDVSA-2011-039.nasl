#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:039. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52523);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2009-2797",
    "CVE-2009-2841",
    "CVE-2010-0046",
    "CVE-2010-0047",
    "CVE-2010-0048",
    "CVE-2010-0049",
    "CVE-2010-0050",
    "CVE-2010-0051",
    "CVE-2010-0052",
    "CVE-2010-0053",
    "CVE-2010-0054",
    "CVE-2010-0314",
    "CVE-2010-0647",
    "CVE-2010-0650",
    "CVE-2010-0651",
    "CVE-2010-0656",
    "CVE-2010-1386",
    "CVE-2010-1387",
    "CVE-2010-1389",
    "CVE-2010-1390",
    "CVE-2010-1391",
    "CVE-2010-1392",
    "CVE-2010-1393",
    "CVE-2010-1394",
    "CVE-2010-1395",
    "CVE-2010-1396",
    "CVE-2010-1397",
    "CVE-2010-1398",
    "CVE-2010-1400",
    "CVE-2010-1401",
    "CVE-2010-1402",
    "CVE-2010-1403",
    "CVE-2010-1404",
    "CVE-2010-1405",
    "CVE-2010-1406",
    "CVE-2010-1407",
    "CVE-2010-1408",
    "CVE-2010-1409",
    "CVE-2010-1410",
    "CVE-2010-1412",
    "CVE-2010-1414",
    "CVE-2010-1415",
    "CVE-2010-1416",
    "CVE-2010-1417",
    "CVE-2010-1418",
    "CVE-2010-1419",
    "CVE-2010-1421",
    "CVE-2010-1422",
    "CVE-2010-1664",
    "CVE-2010-1665",
    "CVE-2010-1758",
    "CVE-2010-1759",
    "CVE-2010-1760",
    "CVE-2010-1761",
    "CVE-2010-1762",
    "CVE-2010-1764",
    "CVE-2010-1766",
    "CVE-2010-1767",
    "CVE-2010-1770",
    "CVE-2010-1771",
    "CVE-2010-1772",
    "CVE-2010-1773",
    "CVE-2010-1774",
    "CVE-2010-1780",
    "CVE-2010-1781",
    "CVE-2010-1782",
    "CVE-2010-1783",
    "CVE-2010-1784",
    "CVE-2010-1785",
    "CVE-2010-1786",
    "CVE-2010-1787",
    "CVE-2010-1788",
    "CVE-2010-1790",
    "CVE-2010-1791",
    "CVE-2010-1792",
    "CVE-2010-1793",
    "CVE-2010-1807",
    "CVE-2010-1812",
    "CVE-2010-1814",
    "CVE-2010-1815",
    "CVE-2010-2264",
    "CVE-2010-2647",
    "CVE-2010-2648",
    "CVE-2010-3113",
    "CVE-2010-3114",
    "CVE-2010-3115",
    "CVE-2010-3116",
    "CVE-2010-3119",
    "CVE-2010-3248",
    "CVE-2010-3255",
    "CVE-2010-3257",
    "CVE-2010-3259",
    "CVE-2010-3812",
    "CVE-2010-3813",
    "CVE-2010-4040",
    "CVE-2010-4197",
    "CVE-2010-4198",
    "CVE-2010-4204",
    "CVE-2010-4206"
  );
  script_bugtraq_id(
    36339,
    36996,
    37925,
    38372,
    38373,
    38684,
    38685,
    38686,
    38687,
    38688,
    38689,
    38690,
    38691,
    38692,
    39804,
    39808,
    40644,
    40646,
    40647,
    40649,
    40650,
    40653,
    40654,
    40655,
    40656,
    40657,
    40658,
    40659,
    40660,
    40661,
    40662,
    40663,
    40665,
    40666,
    40667,
    40668,
    40669,
    40670,
    40671,
    40672,
    40675,
    40697,
    40698,
    40705,
    40707,
    40710,
    40714,
    40726,
    40727,
    40732,
    40750,
    40753,
    40754,
    40756,
    41051,
    41053,
    41572,
    41573,
    41575,
    42034,
    42035,
    42036,
    42037,
    42038,
    42041,
    42042,
    42043,
    42044,
    42045,
    42046,
    42049,
    42494,
    42500,
    43047,
    43077,
    43079,
    43081,
    43083,
    44199,
    44200,
    44201,
    44203,
    44204,
    44206,
    44215,
    44216,
    44217,
    44954,
    44960,
    45718,
    45719,
    45720,
    45721
  );
  script_xref(name:"MDVSA", value:"2011:039");

  script_name(english:"Mandriva Linux Security Advisory : webkit (MDVSA-2011:039)");
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
"Multiple cross-site scripting, denial of service and arbitrary code
execution security flaws were discovered in webkit.

Please consult the CVE web links for further information.

The updated packages have been upgraded to the latest version (1.2.7)
to correct these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64webkitgtk1.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64webkitgtk1.0_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwebkitgtk1.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwebkitgtk1.0_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:webkit-gtklauncher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:webkit-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:webkit1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:webkit1.0-webinspector");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64webkitgtk1.0-devel-1.2.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64webkitgtk1.0_2-1.2.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libwebkitgtk1.0-devel-1.2.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libwebkitgtk1.0_2-1.2.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"webkit-1.2.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"webkit-gtklauncher-1.2.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"webkit-jsc-1.2.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"webkit1.0-1.2.7-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"webkit1.0-webinspector-1.2.7-0.1mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
