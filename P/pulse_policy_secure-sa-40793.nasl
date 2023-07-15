#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103053);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/23");

  script_cve_id("CVE-2017-11455");
  script_bugtraq_id(100530);

  script_name(english:"Pulse Policy Secure Cross-Site Request Forgery (SA40793)");
  script_summary(english:"Checks PPS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pluse Policy
Secure running on the remote host is affected by a cross-site request
forgery vulnerability in diag.cgi. This vulnerability may allow
remote attackers to hijack the authentication of administrators for
requests to start tcpdump.");
  # https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA40793
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8352c00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to  or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11455");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_policy_secure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_policy_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Policy Secure");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");

app_info = vcf::get_app_info(app:'Pulse Policy Secure', port:443);

constraints = [
 {"min_version" : "5.4R1" , "fixed_version" : "5.4R1"},
 {"min_version" : "5.3R1" , "fixed_version" : "5.3R6"},
 {"min_version" : "5.2R1" , "fixed_version" : "5.2R9"},
 {"min_version" : "5.1R1" , "fixed_version" : "5.1R12"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xsrf:TRUE});
