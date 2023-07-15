#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121117);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-5174");

  script_name(english:"Apache Tomcat 7.0.x < 7.0.65 / 8.0.x < 8.0.27 Directory Traversal");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a 
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
instance listening on the remote host is 7.0.x prior to 7.0.65, or
8.0.x prior to 8.0.27. It is, therefore, affected by the following 
vulnerability:
  
  - A directory traversal vulnerability exists in Tomcat when 
    accessing resources via ServletContext methods using paths
    beginning with '/..'. An unauthenticated, remote attacker can 
    exploit this, by sending a specially crafted request, to 
    obtain a directory listing for the directory in which the
    application was deployed. 

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.65");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.27");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.65 / 8.0.27 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5174");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed:make_list("7.0.65", "8.0.27"), severity:SECURITY_WARNING, granularity_regex:"^(7(\.0)?|8(\.0)?)$");

