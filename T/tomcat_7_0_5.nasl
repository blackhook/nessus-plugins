#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51526);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2010-4172");
  script_bugtraq_id(45015);
  script_xref(name:"SECUNIA", value:"42337");

  script_name(english:"Apache Tomcat 6.x < 6.0.30 / 7.x < 7.0.5 Multiple XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat listening on the remote host is 6.x prior to 6.0.30 or 7.x
prior to 7.0.5. It is, therefore, affected by multiple cross-site
scripting vulnerabilities in the Tomcat Manager application's
'sessionList.jsp' file. The 'sort' and 'orderby' parameters are not
properly sanitized before being returned to the user and can be used
to inject arbitrary script into the user's browser.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.

Also note, in the case of Tomcat 7.x, successful exploitation requires
that the cross-site request forgery (CSRF) filter is disabled.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2010/Nov/283");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.30");
  # http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.5_(released_1_Dec_2010)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37871cd8");
  script_set_attribute(attribute:"solution", value:
"Update Apache Tomcat to version 6.0.30 / 7.0.5 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4172");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:make_list("7.0.5", "6.0.30"), severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^[67](\.0)?$");

