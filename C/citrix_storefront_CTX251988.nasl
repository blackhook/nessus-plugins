#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176631);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/02");

  script_cve_id("CVE-2019-13608");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Citrix StoreFront Server XXE (CTX477616)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a XML external entity vulnerability.");
  script_set_attribute(attribute:"description", value:
"Citrix StoreFront Server before 1903, 7.15 LTSR before CU4 (3.12.4000), and 7.6 LTSR before CU8 (3.0.8000) allows XXE 
attacks.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX251988");
  script_set_attribute(attribute:"solution", value:
"Upgrade to versions 3.0.8000 ,3.12.4000, 1903 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13608");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:storefront_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_storefront_win_installed.nbin");
  script_require_keys("installed_sw/Citrix StoreFront");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Citrix StoreFront', win_local:TRUE);

var constraints = [
  { 'min_version' : '3.0', 'fixed_version' : '3.0.8000' },
  { 'min_version' : '3.5', 'fixed_version' : '3.12.4000', },
  { 'min_version' : '3.13', 'fixed_version' : '1903.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);