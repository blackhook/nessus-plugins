##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148406);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/13");

  script_cve_id("CVE-2021-27017");
  script_xref(name:"IAVB", value:"2021-B-0022");

  script_name(english:"Puppet Agent 7.x < 7.4.0 Deserialization");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an deserialization vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Puppet Agent installed on the remote Windows host is 7.x prior to 7.4.0.  It is, therefore, affected by
an deserialization vulnerability. An authenticated, remote attacker can exploit this to execute arbitrary code  on the
target host.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://puppet.com/security/cve/CVE-2021-27017/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Puppet Agent 7.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:puppet:puppet_agent");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("puppet_agent_installed.nbin");
  script_require_keys("installed_sw/Puppet Agent");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Puppet Agent', win_local:TRUE);

constraints = [
  { 'min_version' : '7.0', 'fixed_version' : '7.4.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
