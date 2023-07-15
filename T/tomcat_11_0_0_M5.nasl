#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176289);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id("CVE-2023-28709");
  script_xref(name:"IAVA", value:"2023-A-0266-S");

  script_name(english:"Apache Tomcat 11.0.0.M2 < 11.0.0.M5 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 11.0.0.M5. It is, therefore, affected by a vulnerability
as referenced in the fixed_in_apache_tomcat_11.0.0-m5_security-11 advisory. If non-default HTTP connector settings were
used such that the maxParameterCount could be reached using query string parameters and a request was submitted that
supplied exactly maxParameterCount parameters in the query string, the limit for uploaded request parts could be
bypassed with the potential for a denial of service to occur.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/d53d8e7f77042cc32a3b98f589496a1ef5088e38
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2843d23");
  # https://tomcat.apache.org/security-11.html#Fixed_in_Apache_Tomcat_11.0.0-M5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?797b1b5d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 11.0.0.M5 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28709");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '11.0.0.M5', min:'11.0.0.M2', severity:SECURITY_HOLE, granularity_regex: "^(11(\.0(\.0)?)?)$");
