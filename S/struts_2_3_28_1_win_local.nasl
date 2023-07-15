#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90773);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2016-3081", "CVE-2016-3082", "CVE-2016-3087");
  script_bugtraq_id(87327);

  script_name(english:"Apache Struts 2.x < 2.3.28.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web application that uses a Java framework
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 2.x prior
to 2.3.28.1. It is, therefore, affected by the following
vulnerabilities :

  - An unspecified flaw exists, related to chained
    expressions, when Dynamic Method Invocation (DMI) is
    enabled. An unauthenticated, remote attacker can exploit
    this, via a crafted expression, to execute arbitrary
    code. (CVE-2016-3081)

  - A flaw exists in XSLTResult due to a failure to
    sanitize user-supplied input to the 'location' parameter
    when determining the location of an uploaded stylesheet.
    An unauthenticated, remote attacker can exploit this,
    via a request to a crafted stylesheet, to execute
    arbitrary code. (CVE-2016-3082)

  - A flaw exists that is triggered when dynamic method
    invocation is enabled while using the REST plugin. A
    remote attacker can exploit this, via a specially
    crafted expression, to execute arbitrary code.
    (CVE-2016-3087)
    
Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-031.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-032.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-033.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/version-notes-23281.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.28.1 or later. Alternatively,
apply the workarounds referenced in the vendor advisories.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3082");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Struts Dynamic Method Invocation Expression Handling RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts REST Plugin With Dynamic Method Invocation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include("vcf.inc");

app_info = vcf::combined_get_app_info(app:"Apache Struts");
vcf::check_granularity(app_info:app_info, sig_segments:3);

# Versions 2.3.20.3 and 2.3.24.3 are not affected
if (app_info["version"] == "2.3.20.3" || app_info["version"] == "2.3.24.3")
  audit(AUDIT_INST_PATH_NOT_VULN, ("Apache Struts 2 Application"), app_info["version"], app_info["path"]);

constraints = [
  { "min_version" : "2.0.0", "fixed_version" : "2.3.28.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
