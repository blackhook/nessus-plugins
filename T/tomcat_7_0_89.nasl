#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111066);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-8014", "CVE-2018-8034");
  script_bugtraq_id(104203);

  script_name(english:"Apache Tomcat 7.0.41 < 7.0.90 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple 
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is 
at least 7.0.41 and prior to 7.0.90. It is, therefore, affected by 
multiple vulnerabilities.");
  # https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.89
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8757ab94");
  # https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.90
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45836195");
  # https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5ab19d6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.90 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8014");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/24");

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

tomcat_check_version(fixed:"7.0.90", min:"7.0.41", severity:SECURITY_HOLE, granularity_regex:"^7(\.0)?$");

