#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88884);
  script_version("2.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id(
    "CVE-2015-7941",
    "CVE-2015-7942",
    "CVE-2015-8241"
  );
  script_bugtraq_id(
    74241,
    77621,
    79507
  );

  script_name(english:"AIX 7.2 TL 0 : libxml2 (IV80616)");
  script_summary(english:"Checks the version of the libxml2 packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of libxml2 installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote AIX host has a version of libxml2 installed that is
affected by the following vulnerabilities :

  - A heap-based buffer overflow condition exists in the
    xmlParseEntityDecl() and xmlParseConditionalSections()
    functions within file parser.c due to a failure to
    properly stop parsing invalid input. An unauthenticated,
    remote attacker can exploit this, via specially crafted
    XML data, to cause a denial of service condition or
    potentially disclose sensitive memory contents.
    (CVE-2015-7941)

  - A heap-based buffer overflow condition exists in the
    xmlParseConditionalSections() function within file
    parser.c due to not properly skipping intermediary
    entities. An unauthenticated, remote attacker can
    exploit this, via specially crafted XML data, to cause a
    denial of service condition. (CVE-2015-7942)

  - A buffer overflow condition exists in the xmlNextChar()
    function due to improper bounds checking. A local
    attacker can exploit this, via a malformed XML file, to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2015-8241)");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/libxml2_advisory2.asc");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate interim fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
if ( oslevel != "AIX-7.2" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 7.2", oslevel);
}

oslevelcomplete = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (isnull(oslevelcomplete)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevelparts = split(oslevelcomplete, sep:'-', keep:0);
if ( max_index(oslevelparts) != 4 ) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
ml = oslevelparts[1];
version_report = "AIX " + oslevel + " ML " + ml;
if ( ml != "00")
{
  audit(AUDIT_OS_NOT, "ML 00", version_report);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"7.2", ml:"00", patch:"IV80616s1a", package:"bos.rte.control", minfilesetver:"7.2.0.0", maxfilesetver:"7.2.0.0") < 0) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_get()
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bos.rte.control");
}
