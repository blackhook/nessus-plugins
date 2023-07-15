#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164179);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/08");

  script_cve_id("CVE-2022-2188");
  script_xref(name:"MCAFEE-SB", value:"SB10383");
  script_xref(name:"IAVA", value:"2022-A-0258");

  script_name(english:"McAfee Data Exchange Layer < 6.0.0.280 Privilege Escalation (SB10383)");

  script_set_attribute(attribute:"synopsis", value:
"A security management application running on the remote host is affected by a privilege escalation vulnerability");
  script_set_attribute(attribute:"description", value:
"The instance of McAfee Datat Exchange Layer Broker for Windows installed on the remote host is prior to 6.0.0.280 and 
therefore affected by a privilege escalation vulnerability. This vulnerability potentially allows local users to gain 
elevated privileges by exploiting weak directory controls in the logs directory. This can lead to a denial-of-service 
attack on the DXL Broker.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version");
  # https://kcm.trellix.com/corporate/index?page=content&id=SB10383&actp=null&viewlocale=en_US&showDraft=false&platinum_status=false&locale=en_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aed7e896");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Data Exchange Layer version 6.0.0.280 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2188");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_exchange_layer");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_dxl_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/McAfee Data Exchange Layer Broker");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'McAfee Data Exchange Layer Broker');

var constraints = [{'min_version' : '5.0.0.0' , 'fixed_version': '6.0.0.280'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
