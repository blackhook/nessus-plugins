#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169459);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/24");

  script_cve_id("CVE-2022-45143");
  script_xref(name:"IAVA", value:"2023-A-0014-S");

  script_name(english:"Apache Tomcat 9.0.40 < 9.0.69");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.69. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_9.0.69_security-9 advisory.

  - The JsonErrorReportValve did not escape the type, message or description values. In some circumstances
    these are constructed from user provided data and it was therefore possible for users to supply values
    that invalidated or manipulated the JSON output. (CVE-2022-45143)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/b336f4e58893ea35114f1e4a415657f723b1298e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c2d6150");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.69
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?041d1b23");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.69 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

tomcat_check_version(fixed: '9.0.69', min:'9.0.40', severity:SECURITY_HOLE, granularity_regex: "^9(\.0)?$");
