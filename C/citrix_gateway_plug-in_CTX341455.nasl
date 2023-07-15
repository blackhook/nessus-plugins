#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166439);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id("CVE-2022-21827");

  script_name(english:"Citrix Gateway Plug-in for Windows < 21.9.1.2 Improper Access Control (CTX341455)");

  script_set_attribute(attribute:"synopsis", value:
"Citrix Gateway Plug-in for Windows installed on the remote Windows host is affected by a improper access control vulnerability.");
  script_set_attribute(attribute:"description", value:
"An improper privilege vulnerability has been discovered in Citrix Gateway Plug-in for Windows (Citrix Secure Access for
Windows) < 21.9.1.2 what could allow an attacker who has gained local access to a computer with Citrix Gateway Plug-in
installed, to corrupt or delete files as SYSTEM.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://support.citrix.com/article/CTX341455/citrix-gateway-plugin-for-windows-security-bulletin-for-cve202221827
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d45bbc31");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Gateway Plug-in for Windows version 21.9.1.2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21827");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:gateway_plug-in");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_gateway_plug-in_detect.nbin");
  script_require_keys("installed_sw/Citrix Gateway Plug-in", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Citrix Gateway Plug-in', win_local:TRUE);

constraints = [
  { 'fixed_version' : '21.9.1.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
