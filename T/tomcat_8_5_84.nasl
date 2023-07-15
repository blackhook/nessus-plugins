#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169458);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id("CVE-2022-45143");
  script_xref(name:"IAVA", value:"2023-A-0014-S");

  script_name(english:"Apache Tomcat 8.5.83");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is 8.5.83. It is, therefore, affected by a vulnerability as
referenced in the fixed_in_apache_tomcat_8.5.84_security-8 advisory.

  - The JsonErrorReportValve did not escape the type, message or description values. In some circumstances
    these are constructed from user provided data and it was therefore possible for users to supply values
    that invalidated or manipulated the JSON output. (CVE-2022-45143)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.apache.org/thread/yqkd183xrw3wqvnpcg3osbcryq85fkzj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a5fc161");
  # https://github.com/apache/tomcat/commit/0cab3a56bd89f70e7481bb0d68395dc7e130dbbf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80673291");
  # https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.84
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85816fe4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.5.84 or later.");
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

tomcat_check_version(fixed: '8.5.84', min:'8.5.83', severity:SECURITY_HOLE, granularity_regex: "^8(\.5)?$");
