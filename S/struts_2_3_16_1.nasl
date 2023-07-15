#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117393);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-0050", "CVE-2014-0094");
  script_bugtraq_id(65400, 65999);

  script_name(english:"Apache Struts 2.x < 2.3.16.2 Multiple Vulnerabilities (S2-020)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host uses a Java framework that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 2.x prior to 2.3.16.2. It, therefore, is affected by
multiple vulnerabilities:

  - A denial of service vulnerability exists in MultipartStrea.java in Apache Commons FileUpload due to failure to 
    handle exceptional conditions. A remote, unauthenticated attacker can exploit this issue to cause the application
    to enter an infinite loop which may cause a denial of service condition. (CVE-2014-0050)

  - A class loader manipulation flaw exists in ParameterInterceptor due to improper validation of input data. An
    attacker can exploit this issue to bypass certain security restriction and manipulate the ClassLoader. 
    (CVE-2015-0094)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://cwiki.apache.org/confluence/display/WW/S2-020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2926fce9");
  # https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.3.16.2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e39cc37e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.16.2 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0050");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include('vcf.inc');

app_info = vcf::combined_get_app_info(app:'Apache Struts');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '2.0.0', 'fixed_version' : '2.3.16.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
