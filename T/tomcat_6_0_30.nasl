#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51975);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2010-3718",
    "CVE-2010-4172",
    "CVE-2010-4312",
    "CVE-2011-0013"
  );
  script_bugtraq_id(45015, 46174, 46177);
  script_xref(name:"SECUNIA", value:"42337");
  script_xref(name:"SECUNIA", value:"43194");

  script_name(english:"Apache Tomcat 6.0.x < 6.0.30 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 6.0.x listening on the remote host is prior to 6.0.30. It is,
therefore, affected by multiple vulnerabilities :

  - An error in the access restriction on a 'ServletContext'
    attribute that holds the location of the work directory
    in Tomcat's SecurityManager. A malicious web application
    can modify the location of the working directory which
    then allows improper read and write access to arbitrary
    files and directories in the context of Tomcat.
    (CVE-2010-3718)

  - An input validation error exists in the Manager
    application in that it fails to filter the 'sort' and
    'orderBy' input parameters. (CVE-2010-4172)

  - The default configuration does not include the HTTPOnly
    flag in a Set-Cookie header, which makes it easier for
    remote attackers to hijack a session via script access
    to a cookie. (CVE-2010-4312)

  - An input validation error exists in the HTML manager
    application in that it fails to filter various input
    data before returning it to the browser. (CVE-2011-0013)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.30");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2010/Nov/283");
  script_set_attribute(attribute:"solution", value:
"Update Apache Tomcat to version 6.0.30 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4312");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/14");

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

tomcat_check_version(fixed:"6.0.30", min:"6.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^6(\.0)?$");

