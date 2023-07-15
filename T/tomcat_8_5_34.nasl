#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118036);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-11784");

  script_name(english:"Apache Tomcat 8.5.x < 8.5.34 Open Redirect Weakness");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a open redirect
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is 8.5.x
prior to 8.5.34. It is, therefore, affected by a open redirect 
vulnerability.");
  # http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.34
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bddf0bb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.34 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11784");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

tomcat_check_version(min:"8.5.0", fixed:"8.5.34", severity:SECURITY_WARNING, granularity_regex:"^8(\.5)?$");

