#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106711);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-15706");

  script_name(english:"Apache Tomcat 8.0.45 < 8.0.48 Insecure CGI Servlet Search Algorithm Description Weakness");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a flaw in
 the CGI Servlet search algorithm.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is 8.0.x
prior to 8.0.48. It is, therefore, affected by a flaw that is due to 
the program containing an incorrect description for the CGI Servlet
search algorithm, which may cause an administrator to leave the 
system in an insecure state.");
  # http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.48
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0cdd385");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.0.48 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15706");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"8.0.48", min:"8.0.45", severity:SECURITY_WARNING, granularity_regex:"^8\.0\.$");

