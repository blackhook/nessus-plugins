##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163098);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/08");

  script_cve_id("CVE-2022-23201");
  script_xref(name:"IAVB", value:"2022-B-0021");

  script_name(english:"Adobe RoboHelp 2020 < RH2020.0.8 XSS (APSB22-10)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe RoboHelp installed on the remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe RoboHelp installed on the remote host is 2020 prior to RH2020.0.8. It is, therefore, affected by a
cross-site scripting (XSS) vulnerability. An unauthenticated, remote attacker can exploit this to execute arbitrary
script code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/robohelp/apsb22-10.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe RoboHelp 2020 version RH2020.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23201");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("robohelp_installed.nasl");
  script_require_keys("installed_sw/Adobe RoboHelp 2020");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Adobe RoboHelp 2020');

constraints = [
  { 'min_version' : '2020.0.0', 'fixed_version' : '2020.8.0', 'fixed_display': 'RH2020.0.8'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{'xss':TRUE});
