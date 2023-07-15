#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110904);
  script_version("1.2");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-5314");
  script_bugtraq_id(103186);

  script_name(english:"Citrix NetScaler Authentication Bypass Vulnerability (CTX232199)");
  script_summary(english:"Checks the Citrix NetScaler version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler device is affected by an authentication
bypass vulnerability in the Application Delivery Controller (ADC) and the
Gateway Management Interface that allows the execution of arbitrary,
read only commands on the NetScaler appliance. Please refer to
advisory CTX232199 for more information.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX232199");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix NetScaler ADC and Gateway version 11.0 build 70.16
/ 11.1 build 55.13 / 12.0 build 53.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5314");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_application_delivery_controller_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_access_gateway_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Citrix NetScaler";
version = get_kb_item_or_exit("Host/NetScaler/Version");
build = get_kb_item("Host/NetScaler/Build");
enhanced = get_kb_item("Host/NetScaler/Enhanced");
fixed_build = NULL;

if (isnull(build)) exit(0, "The build number of " + app_name + " " + version + " could not be determined.");

display_version = version + "-" + build;
version = version + "." + build;

if (!enhanced)
{
  # non-enhanced builds
  if (version =~ "^11\.0" && ver_compare(ver:build, fix:"70.12") == 0)
  {
    fixed_build = "70.16";
  }
  else if ((version =~ "^11\.1") && (
  ver_compare(ver:build, fix:"51.21") == 0 ||
  ver_compare(ver:build, fix:"51.26") == 0 ||
  ver_compare(ver:build, fix:"52.13") == 0 ||
  ver_compare(ver:build, fix:"53.11") == 0 ||
  ver_compare(ver:build, fix:"54.14") == 0 ||
  ver_compare(ver:build, fix:"54.16") == 0 ||
  ver_compare(ver:build, fix:"55.10") == 0))
  {
    fixed_build = "55.13";
  }
  else if ((version =~ "^12\.0") && (
  ver_compare(ver:build, fix:"41.16") == 0 ||
  ver_compare(ver:build, fix:"41.22") == 0 ||
  ver_compare(ver:build, fix:"41.24") == 0 ||
  ver_compare(ver:build, fix:"51.24") == 0 ||
  ver_compare(ver:build, fix:"53.6") == 0))
  {
    fixed_build = "53.13";
  }
}

if (isnull(fixed_build))
{
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
}

report =
   '\n  Installed version : ' + display_version +
   '\n  Installed build   : ' + build +
   '\n  Fixed build       : ' + fixed_build +
   '\n';

security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
