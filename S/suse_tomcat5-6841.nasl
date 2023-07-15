#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
  script_id(45472);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902");

  script_name(english: "SuSE Security Update:  Security update for Tomcat 5 (tomcat5-6841)");

  script_set_attribute(attribute: "synopsis", value:
"The remote SuSE system is missing the security patch tomcat5-6841");
  script_set_attribute(attribute: "description", value: "
This update of tomcat5/6 fixes:



 CVE-2009-2693: CVSS v2 Base Score: 5.8
  CVE-2009-2902: CVSS v2 Base Score: 4.3
  Directory traversal vulnerability allowed remote attackers
  to create or overwrite arbitrary files/dirs with a specially crafted
  WAR file.
 CVE-2009-2901: CVSS v2 Base Score: 4.3
  When autoDeploy is enabled the autodeployment process deployed
  appBase files that remain from a failed undeploy, which might allow
  remote attackers to bypass intended authentication requirements
  via HTTP requests.


");
  script_set_attribute(attribute: "solution", value: "Install the security patch tomcat5-6841");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2693");
  script_cwe_id(22, 264);

  script_set_attribute(attribute:"plugin_publication_date", value: "2010/04/09");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat5-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tomcat5-webapps");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english: "SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/SuSE/rpm-list");
  exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"tomcat5-5.0.30-27.42", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"tomcat5-admin-webapps-5.0.30-27.42", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"tomcat5-webapps-5.0.30-27.42", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
