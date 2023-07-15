#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154718);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/17");

  script_cve_id("CVE-2021-40743", "CVE-2021-42731", "CVE-2021-42732");
  script_xref(name:"IAVA", value:"2021-A-0519-S");

  script_name(english:"Adobe InDesign <= 16.4 Multiple Vulnerabilities (APSB21-107)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe InDesign installed on the remote host is prior or equal to 16.4. It is, therefore, affected by
multiple vulnerabilities, as follows:

  - A denial of service (DoS) vulnerability caused by a null pointer dereference that can be exploited by an
    unauthenticated, local attacker. (CVE-2021-40743)

  - Multiple arbitrary code execution vulnerabilities that can be exploited by an unauthenticated, local
    attacker. (CVE-2021-42731, CVE-2021-42732)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/indesign/apsb21-107.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe InDesign version 17.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42731");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:indesign");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_indesign_installed.nbin", "macosx_adobe_indesign_installed.nbin");
  script_require_keys("installed_sw/Adobe InDesign");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;

var app_info = vcf::get_app_info(app:'Adobe InDesign', win_local:win_local);

var constraints = [ { 'fixed_version' : '16.5' , 'fixed_display' : '17.0' } ];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
