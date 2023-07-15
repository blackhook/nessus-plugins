#TRUSTED 77aae0bd0a67e52d040ae930a79cc9fa36a915d1164197073f49493ae451e32e9afcddeb04b5b85a7185ffe95157d95006bacc284bf78d18e89530af5b4c98bd73c9a91434f9d87916c22c8fe2d030a4aaad80e9d8a8c9037857b56b052c98d4b3ef72aef9b1be958ece09834cf9e10879f64487a0c1ac51d39e5c7169e4c41c75552f886938d3a7a0f8c0fcd43c64ce280a89946b308bdf7658d7eb230bfccdb024132566b474f83d22b087a93c0eef34b0238b3091bc102e2ce96448b8b1fe3f017e7df2f998420ea1b11b46358a1a2ee0c2f2b7a378a3a44e17b99317ad53606e5d562a5d370d139c18b068f13e234a3f8a9f6a60194786ed7cdc089ad07f40b5ac85e49722240ee25c587722209ef76c443b33cfbeaaf26c72b161f55c80e6a48ae7ed41f0ccf35aab8e306ca9c962f2a20a5f99c653cab64bdc3ddf1f122ca90525c89fa554e4b1959458ac21ed33a32f5b8247e7a0f1bfb7c32ea46c7b279438b819cd0af7c6f56a4abcc3d4fa115e3b7a711ab7edbd43ce516c0df3de443915edd9d4fb054ee8fc34797b1247365aab95882243b8baa8a4fda845800e2eafdcb52ebe45926635a67c7842ee9b8fe5dab62ef683e39ffbe4ba812181cb35cca7d423300daef5216288e61a16652dc22aef7badcfb9e40dafc18ca0df55ce1a795ecb88ad189cf76d0c393cd8db4e92f3dde77abad1b75b58b7921ecdf3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89963);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id("CVE-2015-8503");

  script_name(english:"Tenable SecurityCenter 5.0.2 Audit File XSS (TNS-2015-12)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"The application installed on the remote host is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Tenable SecurityCenter application
installed on the remote host is affected by a cross-site scripting
(XSS) vulnerability due to improper validation of uploaded .audit
files before they are rendered on the scan results page. An
authenticated, remote attacker can exploit this, via a crafted .audit
file that is later viewed by an administrator, to execute arbitrary
code in the user's browser session.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2015-12");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.2.0.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

version = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(version))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  version = install["version"];
}

# Affects 5.0.2
if (version == "5.0.2")
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  report_items = make_array(
    "Installed version", version,
    "Fixed version", "5.2.0"
  );
  report = report_items_str(report_items:report_items);
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
