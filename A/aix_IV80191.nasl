#%NASL_MIN_LEVEL 999999

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory bind_advisory10.asc.
#
# @DEPRECATED@
#
# Disabled on 2017/07/20. Deprecated by aix_bind_advisory10.nasl.

include("compat.inc");

if (description)
{
  script_id(88969);
  script_version("2.4");
  script_cvs_date("Date: 2018/07/20  0:18:51");

  script_cve_id("CVE-2015-8000");

  script_name(english:"AIX 7.1 TL 4 : bind (IV80191) (deprecated)");
  script_summary(english:"Check for APAR IV80191");

  script_set_attribute(
    attribute:"synopsis", 
    value:"This plugin has been deprecated."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ISC BIND is vulnerable to a denial of service, caused by an error in
db.c when parsing incoming responses. A remote attacker could exploit
this vulnerability to trigger a REQUIRE assertion failure and cause a
denial of service.

This plugin has been deprecated to better accommodate iFix
supersedence with replacement plugin aix_bind_advisory10.nasl (plugin
id 102122)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aix.software.ibm.com/aix/efixes/security/bind_advisory10.asc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use aix_bind_advisory10.nasl (plugin ID 102122) instead.");

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
if ( oslevel != "AIX 7.1" ) audit(AUDIT_OS_NOT, "AIX 7.1", oslevel);

spstring = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
spstringparts = split(spstring, sep:'-', keep:0);
if ( max_index(spstringparts) != 4 ) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
ml = spstringparts[1];
sp = spstringparts[2];
oslevel_description = oslevel + " ML " + ml + " SP " + sp;
if ( ml != "04" || sp != "01" )  audit(AUDIT_OS_NOT, "AIX 7.1 ML 04 SP 01", oslevel_description);

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_7_1_4 = "(IV80191s1a|IV81281m1a)";

if (aix_check_ifix(release:"7.1", ml:"04", sp:"01", patch:ifixes_7_1_4, package:"bos.net.tcp.client", minfilesetver:"7.1.4.0", maxfilesetver:"7.1.4.0") < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bos.net.tcp.client");
}
