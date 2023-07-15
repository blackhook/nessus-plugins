#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111354);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2018-0737");
  script_bugtraq_id(103766);

  script_name(english:"AIX OpenSSL Advisory : openssl_advisory27.asc");
  script_summary(english:"Checks the version of the OpenSSL packages and iFixes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of OpenSSL installed that is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote AIX host is affected by
a side channel attack information disclosure vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/openssl_advisory27.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0737");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_OS_NOT, "AIX");

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

oslevel = oslevel - "AIX-";

if ( oslevel != "5.3" && oslevel != "6.1" && oslevel != "7.1" && oslevel != "7.2")
{
  audit(AUDIT_OS_NOT, "AIX 5.3 / 6.1 / 7.1 / 7.2", "AIX " + oslevel);
}

flag = 0;
package = "openssl.base";

# 1.0.2.1500
if (aix_check_package(release:"5.3", package:package, minpackagever:"1.0.2.500", maxpackagever:"1.0.2.1300", fixpackagever:"1.0.2.1500") > 0) flag++;
if (aix_check_package(release:"6.1", package:package, minpackagever:"1.0.2.500", maxpackagever:"1.0.2.1300", fixpackagever:"1.0.2.1500") > 0) flag++;
if (aix_check_package(release:"7.1", package:package, minpackagever:"1.0.2.500", maxpackagever:"1.0.2.1300", fixpackagever:"1.0.2.1500") > 0) flag++;
if (aix_check_package(release:"7.2", package:package, minpackagever:"1.0.2.500", maxpackagever:"1.0.2.1300", fixpackagever:"1.0.2.1500") > 0) flag++;

# 20.13.102.1500
if (aix_check_package(release:"5.3", package:package, minpackagever:"20.13.102.1000", maxpackagever:"20.13.102.1300", fixpackagever:"20.13.102.1500") > 0) flag++;
if (aix_check_package(release:"6.1", package:package, minpackagever:"20.13.102.1000", maxpackagever:"20.13.102.1300", fixpackagever:"20.13.102.1500") > 0) flag++;
if (aix_check_package(release:"7.1", package:package, minpackagever:"20.13.102.1000", maxpackagever:"20.13.102.1300", fixpackagever:"20.13.102.1500") > 0) flag++;
if (aix_check_package(release:"7.2", package:package, minpackagever:"20.13.102.1000", maxpackagever:"20.13.102.1300", fixpackagever:"20.13.102.1500") > 0) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, package);
}
