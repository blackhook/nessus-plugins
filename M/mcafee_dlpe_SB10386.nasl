#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165182);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/17");

  script_cve_id("CVE-2022-2330");
  script_xref(name:"MCAFEE-SB", value:"SB10386");
  script_xref(name:"IAVA", value:"2022-A-0358");

  script_name(english:"McAfee DLPe < 11.6.600.212 / 11.9.100 (SB10386)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an XML External Entity condition.");
  script_set_attribute(attribute:"description", value:
"The version of the McAfee Data Loss Prevention Endpoint (DLPe) Agent installed on the remote Windows host is prior to
11.6.600.212 or 11.9.100. It is, therefore, affected by a vulnerability caused by improper restriction of XML external
entity references which allows a remote attacker to cause the DLP Agent to access a local service that the attacker
wouldn't usually have access to via a carefully constructed XML file, which the DLP Agent doesn't parse correctly.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kcm.trellix.com/corporate/index?page=content&id=SB10386");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee DLPe 11.6.600.212, 11.9.100 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2330");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_dlpe_agent_installed.nbin");
  script_require_keys("installed_sw/McAfee DLPe Agent", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee DLPe Agent', win_local:TRUE);

var constraints = [
  { 'fixed_version':'11.6.600.212' },
  { 'min_version': '11.9','fixed_version':'11.9.100' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
