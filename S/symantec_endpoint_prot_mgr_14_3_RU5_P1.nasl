#%NASL_MIN_LEVEL 70300
##
#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2009/04/02. Deprecated by symantec_endpoint_prot_client_14_3_RU5_P1.nasl.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(169425);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/13");

  script_cve_id("CVE-2022-37017");
  script_xref(name:"IAVA", value:"2023-A-0001");

  script_name(english:"Symantec Endpoint Protection Manager < 14.3 RU5 Security Control Bypass (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated.");
  # https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/21014
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?017d7aae");
  script_set_attribute(attribute:"solution", value:"n/a.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("installed_sw/Symantec Endpoint Protection Manager");

  exit(0);
}

include('vcf.inc');

exit(0, 'This plugin has been deprecated. Use sambar_cgi_path_disclosure.nasl (plugin ID 11775) instead.');
