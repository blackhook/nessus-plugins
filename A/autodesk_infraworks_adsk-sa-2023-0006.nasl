#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174930);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/29");

  script_cve_id("CVE-2023-25005");
  script_xref(name:"IAVA", value:"2023-A-0224");

  script_name(english:"Autodesk Infraworks RCE (ADSK-SA-2023-0006)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"Applications and services utilizing Autodesk InfraWorks have been affected by a use-after-free vulnerability. The
exploitation of these vulnerabilities may lead to code execution. Hotfixes are available in the Autodesk Access or
the Accounts Portal to help resolve these vulnerabilities.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.autodesk.com/trust/security-advisories/adsk-sa-2023-0006");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Infraworks version 2021.2, 2023.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25005");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:autodesk:infraworks");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("autodesk_infraworks_win_installed.nbin");
  script_require_keys("installed_sw/InfraWorks", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'InfraWorks', win_local:TRUE);

var constraints = [
  # constraints observed from the details of the downloaded patches.
  # unable to download 21 patch due to issue with their server.
  # { 'min_version' : '21', 'fixed_version' : '2021.2.9' },
  { 'min_version' : '23', 'fixed_version' : '23.1.1.17' }

];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
