#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17728);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-2090", "CVE-2007-1355");
  script_bugtraq_id(13873, 24058);

  script_name(english:"Apache Tomcat < 6.0.13 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
instance listening on the remote host is prior to 6.0.13. It is,
therefore, affected by the following vulnerabilities :

  - Requests containing multiple 'content-length' headers
    are not rejected as invalid. This error can allow
    web-cache poisoning, cross-site scripting attacks and
    information disclosure. (CVE-2005-2090)

  - The remote Apache Tomcat install may be vulnerable to
    a cross-site scripting attack if the JSP and Servlet
    examples are enabled. Several of these examples do
    not properly validate user input. (CVE-2007-1355)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.11");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 6.0.13 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-2090");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

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

tomcat_check_version(fixed:"6.0.13", min:"6.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^6(\.0)?$");

