#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122447);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-1336");
  script_bugtraq_id(104898);

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.8 Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a denial of service 
 vulnerability");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Apache Tomcat,
in versions between 9.0.0.M1 and 9.0.7 (inclusive), due to improper 
overflow handling in the UTF-8 decoder component. An unauthenticated, 
remote attacker can exploit this issue, to cause the application to 
stop responding.");
  # http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?682f269a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.8 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1336");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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
tomcat_check_version(fixed:"9.0.8", min:"9.0.0.M1", severity:SECURITY_WARNING);

