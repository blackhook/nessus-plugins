#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130004);
  script_version("1.6");
  script_cvs_date("Date: 2020/01/14");

  script_cve_id("CVE-2019-16097");
  script_xref(name:"VMSA", value:"2019-0015");

  script_name(english:"VMware Harbor 1.7.x < 1.7.6, 1.8.x < 1.8.3 (VMSA-2019-0015)");

  script_set_attribute(attribute:"synopsis", value:
"A cloud native registry installed on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Harbor installed on the remote host is 1.7.x prior to 1.7.6 or 1.8.x prior to 1.8.3. It is,
therefore, affected by a privilege escalation vulnerability in the POST /api/users API endpoint due to insufficient
checks of user privileges. An authenticated, remote attacker can exploit this, via sending a POST to the /api/users
API endpoint, to gain administrator access to the system.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/goharbor/harbor/wiki/Harbor-FAQs#cve-2019-16097");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Harbor version 1.7.6, 1.8.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:goharbor:harbor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cncf_harbor_web_detect.nbin", "cncf_harbor_local_detect.nbin");
  script_require_keys("installed_sw/Harbor");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('installed_sw/Harbor');

app_info = vcf::combined_get_app_info(app:'Harbor');

constraints = [
  { 'min_version' : '1.7', 'fixed_version' : '1.7.6' },
  { 'min_version' : '1.8', 'fixed_version' : '1.8.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
