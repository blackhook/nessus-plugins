#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129821);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/17 14:31:04");

  script_cve_id("CVE-2017-12248");
  script_bugtraq_id(100921);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve76835");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170920-cuic");

  script_name(english:"Cisco Unified Intelligence Center Cross-Site Scripting Vulnerability");
  script_summary(english:"Checks the Cisco Unified Intelligence Center (CUIC) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web framework code of Cisco Unified Intelligence Center Software could allow an
unauthenticated, remote attacker to conduct a cross-site scripting (XSS) attack against a user of the
web interface of an affected system. The vulnerability is due to insufficient input validation of some
parameters that are passed to the web server of the affected software. An attacker could exploit this
vulnerability by persuading a user to click a malicious link or by intercepting a user request and
injecting malicious code into the request. A successful exploit could allow the attacker to execute
arbitrary script code in the context of the affected site or allow the attacker to access sensitive
browser-based information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170920-cuic
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f1cf17a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve76835");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCve76835");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12248");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_intelligence_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_voss_cuic_installed.nbin");
  script_require_keys("installed_sw/Cisco Unified Intelligence Center (CUIC)", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

vcf::add_separator('-');
app_info = vcf::get_app_info(app:'Cisco Unified Intelligence Center (CUIC)');

# known affected releases: 11.5(1), version format is x.x.x.10000-xx
constraints = [
  { 'min_version':'11.5.1', 'fixed_version':'11.5.1.10000-6', 'fixed_display':'11.5(1)ES6 or 12.0(0.99000.828), Bug ID: CSCve76835' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
