##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141835);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/17");

  script_cve_id("CVE-2020-24425");
  script_xref(name:"IAVA", value:"2020-A-0490-S");

  script_name(english:"Adobe Dreamweaver <= 20.2 Privilege Escalation (APSB20-55)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Dreamweaver installed on the remote Windows host is affected by a privilege escalation 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Dreamweaver installed on the remote Windows host is a version prior or equal to 20.2. It is, 
therefore, affected by a privilege escalation vulnerability due to uncontrolled search path functionality. An 
authenticated, local attacker can exploit this to escalate their privileges on an affected host. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/dreamweaver/apsb20-55.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Dreamweaver 21.0 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24425");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:dreamweaver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_dreamweaver_installed.nasl");
  script_require_keys("installed_sw/Adobe Dreamweaver", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Dreamweaver');

constraints = [
  {'fixed_version':'20.3', 'fixed_display':'21.0'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
