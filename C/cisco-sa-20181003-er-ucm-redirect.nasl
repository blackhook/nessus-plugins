#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130069);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2018-15403");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj59218");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170906-cuic");

  script_name(english:"Cisco Emergency Responder Open Redirect (cisco-sa-20181003-er-ucm-redirect)");
  script_summary(english:"Checks the Cisco Emergency Responder (CER) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Emergency Responder (CER) is affected by an open redirect vulnerability.
The vulnerability in the web interface of Cisco Emergency Responder could allow an authenticated, remote attacker to
redirect a user to a malicious web page. The vulnerability is due to improper input validation of the parameters of an
HTTP request. An attacker could exploit this vulnerability by crafting an HTTP request that causes the web interface to
redirect a request to a specific malicious URL. This type of vulnerability is known as an open redirect attack and is
used in phishing attacks that get users to unknowingly visit malicious sites.");
# https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181003-er-ucm-redirect
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bca478c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj59218");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCvj59218");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15403");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:emergency_responder");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_voss_emergency_responder_installed.nbin");
  script_require_keys("installed_sw/Cisco Emergency Responder (CER)", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::get_app_info(app:'Cisco Emergency Responder (CER)');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Known Affected Releases:
# 11.5(4.59000.1)
# 12.0(1.40000.3)
# 12.5(0.98000.110) - defer to assuming affected

# Known Fixed Releases:
# CER.12.5(0.98000.110)
# CER.11.5(4.60000.5)
# CER.11.5(4.59000.3) - use first fixed version, but display latest known patch (11.5(4)SU3)

constraints = [
  { 'min_version':'11.5.0', 'fixed_version':'11.5.4.59000.3', 'fixed_display':'11.5(4)SU3, Bug ID: CSCvj59218' },
  { 'equal':'12.0.1.40000.3', 'fixed_display':'Refer to Bug ID: CSCvj59218' },
  { 'equal':'12.5.0.98000.110', 'fixed_display':'Refer to Bug ID: CSCvj59218' }
];

vcf::cisco_cer::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
