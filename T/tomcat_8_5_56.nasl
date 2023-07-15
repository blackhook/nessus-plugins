#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138097);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-11996");
  script_xref(name:"IAVA", value:"2020-A-0292-S");

  script_name(english:"Apache Tomcat 8.5.0 < 8.5.56 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.56. It is, therefore, affected by a denial of
service vulnerability as referenced in the fixed_in_apache_tomcat_8.5.56_security-8 advisory. Note that Nessus has not
tested for this issue but has instead relied only on the application's self-reported version number.");
  # https://github.com/apache/tomcat/commit/c8acd2ab7371e39aeca7c306f3b5380f00afe552
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a501720");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.56
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ff2bf8c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.56 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11996");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '8.5.56', min:'8.5.0', severity:SECURITY_WARNING, granularity_regex: "^8(\.5)?$");
