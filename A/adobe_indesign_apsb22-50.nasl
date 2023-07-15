#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165183);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/16");

  script_cve_id("CVE-2019-17221");
  script_xref(name:"IAVA", value:"2022-A-0367-S");

  script_name(english:"Adobe InDesign < 17.4 Arbitrary File Read Vulnerability (APSB22-50)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an arbitrary file read vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote host is prior to 17.4. It is, therefore, affected by an
arbitrary file read vulnerability. A remote, unauthenticated attacker can exploit this to read arbitrary files.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb22-50.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 17.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17221");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin", "macosx_adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:win_local);

var constraints = [ { 'fixed_version' : '17.4' } ];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
