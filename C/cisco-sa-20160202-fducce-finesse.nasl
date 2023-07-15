#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130065);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/30 13:24:46");

  script_cve_id("CVE-2016-1307");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw79085");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160202-fducce");

  script_name(english:"Cisco Finesse Appliance Authentication Bypass Vulnerability (cisco-sa-20160202-fducce)");
  script_summary(english:"Checks the Cisco Finesse appliance version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Finesse appliance is affected by an authentication bypass
vulnerability exists in Extensible Messaging and Presence Protocol (XMPP) due to a default account with a static
password. An unauthenticated, remote attacker can exploit this, via using the default account, to bypass authentication
and execute arbitrary actions with user privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160202-fducce
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3b7e6d8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw79085");
  script_set_attribute(attribute:"solution", value:
"Apply the patch or upgrade to the version recommended in Cisco bug ID CSCuw79085");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1307");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:finesse");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_voss_finesse_installed.nbin");
  script_require_keys("installed_sw/Cisco VOSS Finesse");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

app_info = vcf::cisco_finesse::get_app_info(app:'Cisco VOSS Finesse');

constraints = [
  { 'min_version':'10.5.1.10000.3',  'max_version':'10.5.1.10000.3',  'fixed_display' : 'Refer to Cisco Bug ID: CSCuw79085' },
  { 'min_version':'11.0.1.10000.1',  'max_version':'11.0.1.10000.1',  'fixed_display' : 'Refer to Cisco Bug ID: CSCuw79085' }
];

vcf::cisco_finesse::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
