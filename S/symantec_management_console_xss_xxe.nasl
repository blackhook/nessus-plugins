#
# (C) Tenable Network Security, Inc.
#




include("compat.inc");

if (description)
{
  script_id(102203);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-6322", "CVE-2017-6323");

  script_name(english:"Symantec Management Console Multiple XSS and XXE Vulnerabilities (SYM17-005)");
  script_summary(english:"Checks version of Symantec Management Console.");

  script_set_attribute(attribute:"synopsis", value:
"The Symantec Management Console on the target host is affected by
multiple XSS and XXE vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Manager Console running on the remote host is
earlier then ITM 8.1 RU1, ITMS 8.0_POST_HF6 or ITMS 7.6_POST_HF7 and
is therefore affected by multiple cross-site scripting (XSS) and
XML External Entity (XXE) processing vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-294/");
  # https://support.symantec.com/en_US/article.SYMSA1235.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b7c02d7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Management Console ITMS 8.1 RU1 or later or apply
patches ITMS 8.0_POST_HF6 and ITMS 7.6_POST_HF7.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6323");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:altiris_it_management_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_management_console_detect.nbin");
  script_require_keys("installed_sw/Symantec Management Console", "Settings/ParanoidReport", "SMB/Registry/Enumerated");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("smb_func.inc");
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixed_builds = make_array(
  "7.6.0.0", "7.6.1655.0",
  "8.0.0.0", "8.0.3769.0",
  "8.1.0.0", "8.1.5088.0"
);

install = get_single_install(app_name:"Symantec Management Console", exit_if_unknown_ver:TRUE);
build = install["version"];
path = install["path"];

foreach product_branch (keys(fixed_builds))
{
  # Check if the version is vulnerable, but make sure it's the right major/minor version too
  if (ver_compare(fix:product_branch, ver:build) >= 0 &&
      ver_compare(fix:fixed_builds[product_branch], ver:build) == -1)

  fixed_build = fixed_builds[product_branch];
}

if (! empty_or_null(fixed_build))
{

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (isnull(path)) path = 'n/a';

  report = '\n  Path                    : '+path+
           '\n  Installed build version : '+build+
           '\n  Fixed build version     : '+fixed_build+'\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report, xss:TRUE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Symantec Management Console",  build);
