#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79253);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/07");

  script_cve_id("CVE-2014-2334", "CVE-2014-2335", "CVE-2014-2336");
  script_bugtraq_id(70887, 70889, 70890);

  script_name(english:"Fortinet FortiAnalyzer / FortiManager < 5.0.7 Multiple Unspecified XSS (FG-IR-14-033)");
  script_summary(english:"Checks version of FortiAnalyzer and FortiManager");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of FortiAnalyzer or FortiManager
prior to 5.0.7. It is, therefore, affected by multiple unspecified
cross-site scripting vulnerabilities due to the web UI not properly
validating input before returning it to users. An attacker can exploit
these vulnerabilities to execute code in the security context of a
user's browser.");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/psirt/FG-IR-14-033");
  script_set_attribute(attribute:"see_also", value:"https://docs.fortinet.com/d/fortianalyzer-v5.0.7-release-notes");
  script_set_attribute(attribute:"see_also", value:"https://docs.fortinet.com/d/fortimanager-v5.0.7-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiAnalyzer / FortiManager version 5.0.7 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2334");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortianalyzer_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortimanager_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build");

  exit(0);
}

include("vcf.inc"); 

name = "FortiAnalyzer / FortiManager";
# Using kb source to grab the model to check for FortiAnalyzer / FortiManager
app_info = vcf::get_app_info(app:"FortiAnalyzer",
                              kb_ver:"Host/Fortigate/version",
                              kb_source:"Host/Fortigate/model");

if( "FortiAnalyzer" >!< app_info.source )
{
  if ( "FortiManager" >!< app_info.source )
      audit(AUDIT_HOST_NOT, "a " + name + " device");
  else
    app_info.app = "FortiManager";
}

constraints = [
  { "fixed_version" : "5.0.7" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
