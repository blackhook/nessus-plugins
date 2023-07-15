#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(152700);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2018-0732");

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory28.asc");
  
  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote AIX host is affected
by a denial of service vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/openssl_advisory28.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0732");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include('aix.inc');
include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item('Host/AIX/version') ) audit(AUDIT_OS_NOT, 'AIX');
if ( ! get_kb_item('Host/AIX/lslpp') ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item('Host/AIX/emgr_failure' ) ) exit(0, 'This AIX package check is disabled because : '+get_kb_item('Host/AIX/emgr_failure') );

var flag = 0;
var package = 'openssl.base';

if (aix_check_ifix(release:'5.3', patch:'(102oa_ifix)', package:package, minfilesetver:'1.0.2.500', maxfilesetver:'1.0.2.1500') < 0) flag++;
if (aix_check_ifix(release:'6.1', patch:'(102oa_ifix)', package:package, minfilesetver:'1.0.2.500', maxfilesetver:'1.0.2.1500') < 0) flag++;
if (aix_check_ifix(release:'7.1', patch:'(102oa_ifix)', package:package, minfilesetver:'1.0.2.500', maxfilesetver:'1.0.2.1500') < 0) flag++;
if (aix_check_ifix(release:'7.2', patch:'(102oa_ifix)', package:package, minfilesetver:'1.0.2.500', maxfilesetver:'1.0.2.1500') < 0) flag++;

if (aix_check_ifix(release:'5.3', patch:'(fips_102oa)', package:package, minfilesetver:'20.13.102.1000', maxfilesetver:'20.13.102.1500') < 0) flag++;
if (aix_check_ifix(release:'6.1', patch:'(fips_102oa)', package:package, minfilesetver:'20.13.102.1000', maxfilesetver:'20.13.102.1500') < 0) flag++;
if (aix_check_ifix(release:'7.1', patch:'(fips_102oa)', package:package, minfilesetver:'20.13.102.1000', maxfilesetver:'20.13.102.1500') < 0) flag++;
if (aix_check_ifix(release:'7.2', patch:'(fips_102oa)', package:package, minfilesetver:'20.13.102.1000', maxfilesetver:'20.13.102.1500') < 0) flag++;

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:'[()]', replace:'');
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:'[|]', replace:' or ');
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:aix_report_extra);
}
else
{
    tested = aix_pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, package);
}
