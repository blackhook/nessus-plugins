##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147421);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2021-21068", "CVE-2021-21069", "CVE-2021-21078");
  script_xref(name:"IAVA", value:"2021-A-0124-S");

  script_name(english:"Adobe Creative Cloud Desktop < 5.4 Multiple Vulnerabilities (APSB21-18)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Creative Cloud Desktop installed on the remote host is prior to version 5.4. It is, therefore,
affected by multiple vulnerabilities, including the following:

  - An arbitrary file write vulnerability that leads to arbitrary code execution. (CVE-2021-21068)

  - An OS command injection vulnerability that leads to arbitrary code execution. (CVE-2021-21078)

  - Improper input validation that can allow an attacker to elevate their privileges. (CVE-2021-21069)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb21-18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e798cb5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Creative Cloud Desktop version 5.4.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21069");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_creative_cloud_installed.nbin", "macosx_adobe_creative_cloud_installed.nbin");
  script_require_ports("installed_sw/Adobe Creative Cloud", "installed_sw/Creative Cloud");

  exit(0);
}

include('vcf.inc');

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
{
  win_local = TRUE;
  app = 'Adobe Creative Cloud';
}
else
{
  win_local = FALSE;
  app = 'Creative Cloud';
}

get_kb_item_or_exit('installed_sw/' + app);

app_info = vcf::get_app_info(app:app, win_local:win_local);

constraints = [
  {'fixed_version' : '5.4' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
