#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111069);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2018-8014");
  script_bugtraq_id(104203, 104894, 104895);

  script_name(english:"Apache Tomcat 9.0.0 < 9.0.10 Multiple Vulnerabilites");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is 9.0.x
prior to 9.0.10. It is, therefore, affected by multiple 
vulnerabilities.
  A security misconfiguration vulnerability exists in Apache Tomcat
  prior to version 9.0.9 due to insecure default settings for the 
  CORS filter (CVE-2018-8014).
  
  A security misconfiguration vulnerability exists in Apache Tomcat 
  prior to version 9.0.10. Hostname validation was not enabled by 
  default when using TLS with the WebSocket client (CVE-2018-8034).

  An information disclosure vulnerability exists in Apache Tomcat
  prior to version 9.0.10 due to a race condition. If an async
  request was completed by the application at the same time as the 
  container triggered the async timeout, this could lead to a user
  being sent the response of another user (CVE-2018-8037).");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1831726");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.9 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8014");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '9.0.9', min:'9.0.0', severity:SECURITY_HOLE, granularity_regex: "^9(\.0)?$");
