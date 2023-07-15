##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146620);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/25");

  script_cve_id(
    "CVE-2021-23878",
    "CVE-2021-23881",
    "CVE-2021-23882",
    "CVE-2021-23883"
  );
  script_xref(name:"MCAFEE-SB", value:"SB10345");
  script_xref(name:"IAVA", value:"2021-A-0102");

  script_name(english:"McAfee Endpoint Security for Windows < 10.6.1 / 10.7.0 February 2021 Update Multiple Vulnerabilities (SB10345)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Endpoint Security (ENS) for Windows installed on the remote Windows host is affected by
multiple vulnerabilities, as follows:

  - Clear text storage of sensitive Information in memory vulnerability in McAfee Endpoint Security (ENS) for 
    Windows prior to 10.7.0 February 2021 Update allows a local user to view ENS settings and credentials via 
    accessing process memory after the ENS administrator has performed specific actions. To exploit this, the 
    local user has to access the relevant memory location immediately after an ENS administrator has made a 
    configuration change through the console on their machine. (CVE-2021-23878)
  
  - A stored cross site scripting vulnerability in ePO extension of McAfee Endpoint Security (ENS) prior to 
    10.7.0 February 2021 Update allows an ENS ePO administrator to add a script to a policy event which will 
    trigger the script to be run through a browser block page when a local non-administrator user triggers the 
    policy. (CVE-2021-23881)
  
  - Improper Access Control vulnerability in McAfee Endpoint Security (ENS) for Windows prior to 
    10.7.0 February 2021 Update allows local administrators to prevent the installation of some ENS files by 
    placing carefully crafted files where ENS will be installed. This is only applicable to clean installations 
    of ENS as the Access Control rules will prevent modification prior to an upgrade. (CVE-2021-23882)
  
  - A Null Pointer Dereference vulnerability in McAfee Endpoint Security (ENS) for Windows prior to 
    10.7.0 February 2021 Update allows a local administrator to cause Windows to crash via a specific system call 
    which is not handled correctly. This varies by machine and had partial protection prior to this update. 
    (CVE-2021-23883)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10345");
  script_set_attribute(attribute:"solution", value:
"Apply the 10.7.0 or 10.6.1 February 2021 Update or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23878");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:endpoint_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_endpoint_security_installed.nbin");
  script_require_keys("installed_sw/McAfee Endpoint Security Platform", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'McAfee Endpoint Security Platform', win_local:TRUE);

# Build numbers: https://kc.mcafee.com/corporate/index?page=content&id=KB82761, use "Common Client"
constraints = [
  { 'min_version':'10.6.0.000', 'fixed_version':'10.6.1.2286', 'fixed_display':'ENS 10.6.1 February 2021 Update' },
  { 'min_version':'10.7.0.000', 'fixed_version':'10.7.0.2421', 'fixed_display':'ENS 10.7.0 February 2021 Update' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{xss:TRUE}
);
