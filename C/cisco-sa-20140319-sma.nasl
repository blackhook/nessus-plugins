#TRUSTED 539d99c630d3d4ab06d8cdd4f256bf3a943a91344a1b01ef37d4c2ec38095ab500a63ebc18d224d2363490dffea1c0cf1cb7808471924d8ee6dda5ebe277cf8e5a164ad6aced8fb64644fa86228ecb271cfb54b3f7faeb55231eeecbf6a1a5f2e9f755f2d6a7b2bf7702693dfdb0b4d726cad64abe5c25f8bb80d4049c72d475bc49c429a658eddef88cc37a147e1c1cbac8be8e7edb4bdc0d99e292fc1ec5827dfb93739fa970a97a7d41863af5b18155d31f8bfd4adb0c2a59a6e354d1c3541ab26b949648df9dce00af4e88c8ff8025a564c9b84919e0e314dc143709d9585f5929240a3f482bc8e07232fc4aa17fa5cfc39706f4ee1548350d05cae0f7096ccd5fc3392bf30f2a2564eb61a58739df9f8abc5dfb9d6c9e0b20a9d20c65d9301217d30b0db67f6d73f80ad8a75e7379b2d31a208707b323f4d24b07d5d9902b4d6977e718322a7b4d355de0e9f8980cda81306aa2f1ec456652eb2d29624bd8d121e583c48ad4c7d33f659b9858f5dae09c93b6069b606f1cd8dd3fea9625eb8b66781444d714b11f67de8dca1441cd66ca5b400cb26287b87efab3383d8505e06c12d10b0c4747dff65a36bd4f90913d0ef0569f6896ce93adc2ce8b86a495dbd8aafdbb88c087b230b7727f30e536a5e21102c462126095875b2ca80188c966fb7a52dce52b84e643ad5a9409db9f1ff89b3bd5967be643156425de5238
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73211);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-2119");
  script_bugtraq_id(66309);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug80118");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140319-asyncos");

  script_name(english:"Cisco AsyncOS for Content Security Management Appliances Software Remote Code Execution (CSCug80118)");
  script_summary(english:"Checks SMA version");

  script_set_attribute(attribute:"synopsis", value:"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco Content
Security Management Appliance running on the remote host is affected
by a remote code execution vulnerability due to a flaw in Cisco
AsyncOS. An authenticated attacker could potentially exploit this
vulnerability to execute arbitrary code with the privileges of the
'root' user.

Note: In order to exploit this vulnerability, the FTP service and
Safelist/Blocklist (SLBL) service must be enabled.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140319-asyncos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c66d063e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20140319-asyncos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");
  script_require_ports("Services/ftp", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Content Security Management Appliance/Version');

vuln = FALSE;

if (get_kb_item("Host/local_checks_enabled")) local_checks = TRUE;
else local_checks = FALSE;

if (ver =~ "^[0-6]\." || ver =~ "^7\.[012]\.") # 7.2 and earlier
  display_fix = '7.9.1-110';
else if (ver =~ "^7\.7\.")
  display_fix = '7.9.1-110';
else if (ver =~ "^7\.8\.")
  display_fix = '7.9.1-110';
else if (ver =~ "^7\.9\.")
  display_fix = '7.9.1-110';
else if (ver =~ "^8\.0\.")
  display_fix = '8.1.1-013';
else if (ver =~ "^8\.1\.")
  display_fix = '8.1.1-013';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco SMA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

# Compare version to determine if affected. FTP must also be enabled
# or paranoia setting must be above 1.
if (
  ver_compare(ver:ver, fix:fix, strict:FALSE) == -1 &&
  (get_kb_list("Services/ftp") || report_paranoia > 1)
) vuln = TRUE;

# If local checks are enabled, confirm whether SLBL service is
# enabled. If they are not, only report if running a paranoid scan.
if (local_checks && vuln)
{
  vuln = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/slblconfig", "slblconfig");
  if (check_cisco_result(buf) && preg(multiline:TRUE, pattern:"Blocklist: Enabled", string:buf))
    vuln = TRUE;
}
else if (!local_checks && report_paranoia < 2) vuln = FALSE;

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + display_fix +
      '\n';

    if (!local_checks) report +=
      '\n' + 'Nessus was unable to determine whether the End-User Safelist /' +
      '\n' + 'Blocklist service is running because local checks are not' +
      '\n' + 'enabled.' +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco SMA', display_ver);
