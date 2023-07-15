#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151468);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/09");

  script_cve_id("CVE-2020-12596");
  script_xref(name:"IAVA", value:"2021-A-0300");

  script_name(english:"Symantec Endpoint Protection Manager < 14.3 RU2 Session Token Exposure (SYMSA18255)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Manager installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager (SEPM) installed on the remote host is prior to 14.3 RU2. It is
therefore affected by a vulnerability. HTTPS GET parameters may include session tokens, which could be logged.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://support.broadcom.com/security-advisory/content/security-advisories/Symantec-Security-Update/SYMSA18255
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1838de42");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Manager version 14.3 RU2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12596");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_endpoint_prot_mgr_installed.nasl");
  script_require_keys("installed_sw/Symantec Endpoint Protection Manager");

  exit(0);
}

include('vcf.inc');

# https://knowledge.broadcom.com/external/article/154575
var constraints = [
  { 'fixed_version' : '14.3.4615.2000' }
];

var app_info = vcf::get_app_info(app:'Symantec Endpoint Protection Manager', win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
