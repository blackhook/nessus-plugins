#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121122);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-4322", "CVE-2013-4590");

  script_name(english:"Apache Tomcat < 8.0.0-RC10 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
instance listening on the remote host is prior to 8.0.0-RC10. It is,
therefore, affected by multiple vulnerabilities:

  - The fix for CVE-2012-3544 was not complete and limits
    are not properly applied to chunk extensions and
    whitespaces in certain trailing headers. This error
    could allow denial of service attacks. (CVE-2013-4322)

  - The application allows XML External Entity (XXE)
    processing that could disclose sensitive information.
    (CVE-2013-4590)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.0-RC10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ce2c587");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.0.0-RC10 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4590");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/26");
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

include("tomcat_version.inc");

tomcat_check_version(fixed:"8.0.0-RC6", fixed_display:"8.0.0-RC10", min:"8.0.0", severity:SECURITY_WARNING, granularity_regex:"^8(\.0)?$");

