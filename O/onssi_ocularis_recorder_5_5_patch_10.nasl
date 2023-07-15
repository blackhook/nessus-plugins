#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111384);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-3852");
  script_xref(name:"IAVB", value:"2018-B-0090");

  script_name(english:"OnSSI Ocularis Recorder 5.5 < Patch 10 / 5.4 < Patch 19 / 5.3 < Patch 19 Denial of Service (DoS) Vulnerability");
  script_summary(english:"Checks the Ocularis Recorder version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OnSSI Ocularis Recorder installed on the remote
Windows host is 5.5 prior to Patch 10, 5.4 prior to Patch 19, or 5.3
prior to Patch 19. It is, therefore, affected by a denial of service
vulnerability.");
  # https://blog.talosintelligence.com/2018/06/vulnerability-spotlight-talos-2018-0535.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd1a0d6f");
  # https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0535
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3f3a3ff");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OnSSI Ocularis 5.5 Patch 10, 5.4 Patch 19, or 5.3 Patch
19 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3852");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:onssi:ocularis");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("onssi_ocularis_recorder_installed.nbin");
  script_require_keys("installed_sw/Ocularis Recorder", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
app = "Ocularis Recorder";
app_info = vcf::get_app_info(app:app, win_local:TRUE);

version = app_info["version"];
path = app_info["path"];
patch = app_info["Patch"];

fix_patch = NULL;
if (version =~ "^5\.5$")
  fix_patch = "10";
else if (version =~ "^5\.[34]$")
  fix_patch = "19";

if (isnull(fix_patch))
  audit(AUDIT_INST_VER_NOT_VULN, app, version + " Patch " + patch);

if (ver_compare(ver:patch, fix:fix_patch) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version + " Patch " + patch +
    '\n  Fixed version     : ' + version + " Patch " + fix_patch +
    '\n';

  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, version + " Patch " + patch);
