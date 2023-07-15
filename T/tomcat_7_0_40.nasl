#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66428);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-2071", "CVE-2013-4444");
  script_bugtraq_id(59798, 69728);

  script_name(english:"Apache Tomcat 7.0.x < 7.0.40 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple 
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.0 listening on the remote host is prior to 7.0.40. It is,
therefore, affected by multiple vulnerabilities :
 
  - An error exists related to 'AsyncListeners' that throw
    'RuntimeExceptions' that allow elements of certain
    requests to be disclosed in responses to other requests.
    (CVE-2013-2071)

  - It is possible to upload a malicious JSP to a Tomcat
    server and subsequently trigger execution of that JSP.
    (CVE-2013-4444)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/533399/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.40");
  script_set_attribute(attribute:"solution", value:
"Update to Apache Tomcat version 7.0.40 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4444");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"7.0.40", min:"7.0.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");

