#TRUSTED ac314363415d6a4e35462245acf71f9de65dbd05c3721e78f155e9dc2a94812f98009f498437a99a4cb2be51a24698f9ae79bae3a344899bbb905e764e130c55d29ebe1ab097ac06e09d73f6b53a65e3d2ab989c5be8311b1d04c6004993032f41b5e3da50cf40d65b1455d4a697cd148d7bfe4dbb91f0fed8c5c545b442909c4e54ccef6ace2b5591f6801647d2272119050d45c663437dda1df6baaa3dafed54ebc63d6e04db4a0f7327a8350364a274abb551f113b3cb638188ca7c23c6aa589670fcba8306cd7d9152175a9827f608924a063bb9774172239824daae8af95cb85751c1f36b96339632a969b582952393178d19162e97f461ba276b9ce7a24b558e5c6bb73fcfb91cd9984e13c4cbf861eb77ae0bcda255617b5e2a2e0772eba72437080b06c0ae923bdcdcbf33ab02b1fb64b4c5fe72354d05cda0820bcf302061c50a4214080031f4051509beb7a4502e21cf84f42dd64d02c751e6ea5aa81de1e272a77d31e823d79f896841260bff4b9d4ee8fca2a6e0a9d5b382b89aa87c42b3aedae7ed79433671b5c62dbc4a366bd798be576f2bd43168b48d155279b21821fac3b32061ef62657792def15441e4a7c7fca89607bca476e87b2334737fefdea11b4f725adad11d9ac6c1d55b566768825514590da67e6b2197baf44a4b974500d97a2f2897b514e5ddad7bbc9a9cb76a6492ca53b12e49fd66496d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79359);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3398");
  script_bugtraq_id(70230);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq65542");

  script_name(english:"Cisco ASA SSL VPN Information Disclosure (CSCuq65542)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of the Cisco ASA software on the
remote device is affected by an information disclosure vulnerability
in the SSL VPN feature. By requesting a specific URL, a remote
attacker can exploit this vulnerability to obtain software version
information which could be used for reconnaissance attacks.

Note that the SSL VPN feature must be enabled for the device to be
affected by this vulnerability.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=35946
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90ac6b01");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35946");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in Cisco bug ID CSCuq65542.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/20");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa   = get_kb_item_or_exit('Host/Cisco/ASA');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

fixed_ver = NULL;

if (ver =~ "^8\.4[^0-9]" && check_asa_release(version:ver, patched:"8.4(7.23)"))
  fixed_ver = "8.4(7.23)";

else if (ver =~ "^8\.6[^0-9]")
  fixed_ver = "Refer to the vendor.";

else if (ver =~ "^9\.0[^0-9]" && check_asa_release(version:ver, patched:"9.0(4.25)"))
  fixed_ver = "9.0(4.25)";

else if (ver =~ "^9\.1[^0-9]" && check_asa_release(version:ver, patched:"9.1(5.15)"))
  fixed_ver = "9.1(5.15)";

else if (ver =~ "^9\.2[^0-9]" && check_asa_release(version:ver, patched:"9.2(2.7)"))
  fixed_ver = "9.2(2.7)";

if (isnull(fixed_ver))
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", ver);

flag     = FALSE;
override = FALSE;

# Check if SSL VPN (WebVPN) feature is enabled
if (get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_webvpn", "show running-config webvpn");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"enable", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
