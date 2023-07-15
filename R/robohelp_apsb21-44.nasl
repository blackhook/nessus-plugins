#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(150716);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2021-28588");
  script_xref(name:"IAVB", value:"2021-B-0034-S");

  script_name(english:"Adobe RoboHelp Server <= 2019.0.9 Arbitrary Code Execution (APSB21-44)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe RoboHelp Server installed on the remote host is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe RoboHelp Server installed on the remote host is less than or equal to 2019.0.9. It is, therefore,
affected by an arbitrary code execution vulnerability as referenced in the apsb21-44 advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/robohelp-server/apsb21-44.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d148ae78");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe RoboHelp Server version 2020.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28588");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("robohelp_server_installed.nasl");
  script_require_keys("installed_sw/Adobe RoboHelp Server");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Adobe RoboHelp Server'); 

constraints = [
  { 'fixed_version' : '2019.0.10', 'fixed_display': 'RH2020.0.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
