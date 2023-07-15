#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131232);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/08");

  script_cve_id("CVE-2019-16001");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq87642");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191120-webex-teams-dll");

  script_name(english:"Cisco Webex Teams for Windows DLL Hijacking Vulnerability (cisco-sa-20191120-webex-teams-dll)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Webex Teams is affected by a DLL
hijacking vulnerability. An authenticated, local attacker can exploit this, by
crafting a malicious DLL file and placing it in a specific location, to execute
arbitrary code on the target machine with the privileges of another user
account. Please refer to the Cisco BIDs and Cisco Security Advisory for more
information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191120-webex-teams-dll
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4213ada");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq87642");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16001");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(427);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_teams");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_webex_teams_installed_win.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Webex Teams");

  exit(0);
}

include('vcf.inc');

app = 'Webex Teams';

app_info = vcf::get_app_info(app:app, port:port, win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
    { 'max_version': '3.0.13588.0', 'fixed_display': 'Consult Vendor Advisory' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
