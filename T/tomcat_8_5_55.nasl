#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136807);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-9484");
  script_xref(name:"IAVA", value:"2020-A-0225-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Apache Tomcat 8.5.x < 8.5.55 Remote Code Execution");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a remote code execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 8.5.x prior to 8.5.55. It is, therefore, affected by a 
remote code execution vulnerability as referenced in the fixed_in_apache_tomcat_8.5.55_security-8 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.55
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9502c510");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.55 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9484");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");

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

tomcat_check_version(
  min:'8.5.0',
  fixed: '8.5.55',
  severity:SECURITY_WARNING,
  granularity_regex: "^8(\.5)?$"
);

