#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46867);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2008-0128", "CVE-2008-1232", "CVE-2008-2370");
  script_bugtraq_id(27365, 30494, 30496);
  script_xref(name:"SECUNIA", value:"28552");
  script_xref(name:"SECUNIA", value:"31379");

  script_name(english:"Apache Tomcat 4.x < 4.1.39 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 4.x listening on the remote host is prior to 4.1.39. It is,
therefore, affected by one or more of the following vulnerabilities :

  - If the remote Apache Tomcat install is configured to use
    the SingleSignOn Valve, the JSESSIONIDSSO cookie does
    not have the 'secure' attribute set if authentication
    takes place over HTTPS. This allows the JSESSIONIDSSO
    cookie to be sent to the same server when HTTP content
    is requested. (CVE-2008-0128)

  - The remote Apache Tomcat install is vulnerable to a
    cross-site scripting attack. Improper input validation
    allows a remote attacker to inject arbitrary script
    code or HTML into the message argument used by the
    HttpServletResponse.sendError method. (CVE-2008-1232)

  - If the remote Apache Tomcat install contains pages
    using the RequestDispatcher object, a directory
    traversal attack may be possible. This allows an
    attacker to select one or more of the input parameters
    and provide specific values leading to access of
    potentially sensitive files. (CVE-2008-2370)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.39");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 4.1.39 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0128");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 22, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"4.1.39", min:"4.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^4(\.1)?$");

