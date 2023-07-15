#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150797);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/02");

  script_cve_id("CVE-2021-20099", "CVE-2021-20100");
  script_xref(name:"IAVB", value:"2021-B-0039");

  script_name(english:"Tenable Nessus Agent < 8.2.5 Multiple Vulnerabilities (TNS-2021-12)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus Agent installed on the remote Windows system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus agent running on the remote Windows host is prior to 8.2.5. 
It is, therefore, affected by multiple vulnerabilities:

  - Multiple local privilege escalation vulnerabilities. A local attacker can exploit these to gain administrator
    privileges to the system. (CVE-2021-20099, CVE-2021-20100)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus Agent version 8.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20100");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_nessus_agent_installed_win.nbin");
  script_require_keys("installed_sw/Tenable Nessus Agent", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Tenable Nessus Agent');

var constraints = [
  { 'fixed_version' : '8.2.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

