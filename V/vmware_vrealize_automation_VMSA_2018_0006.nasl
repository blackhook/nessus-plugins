#TRUSTED 60da2fdad8132ef8c9397fe9e47955a7fb01297875b58347767b4c5db0fecd63c1a6430450f0d027541bcfcd5e6421d663e0142a3abea51ec037036667a9edcfa70ee08441b45695bdffb03dc98758e32f7ca1c087236c9ab5f07760903989f9f5d00c20a26f86571edd728dd8dd8aa3dae67bba59d965f9e9a05719fe0387304bdd9a9787dd6ccef7496dd9429cae1005596037e6ac9fadfb5ebb21bed6aebd93f9edbdb3e64cc11b11450bf1bff408d1de0cea1885285a9605bb4e191067f9a6cef203556a6b9943d29d18a35d24a8f56d6f3d2d86a1faf7026e0d71351ad87d5b79502c491759eeef0da39359b029df5ffe545ee7836d1ea968dbd4467d9f51c352dbf109444e77de35be1ffd3d18ef6947ee0b321d19ea384718c0c39c2b61326b02b94d48d02e28f04a4ef2b9d47eac648fe5c247111eeb2ddf67975b93b396f952c1f1b4af2365d452f3398ec60ec1e7fda21381c1639928ba7e21b0548269f6b5829812031f6ac9f250495f072173b5598bbe684c726b045a3e4a9e6378e6a6704445d0f55e6917688c64be36daf03ca288cab9e4cb473ffb9e5c58699fd0cd7616873dc9e511cdd3862bdc9c51804bea3b6a96ca910eaef56996b918d3f3a3ecbdcb2ae76abdc13183b5fae51ae49d4a15921f1f8edf2b4c0ba408b597da2cbe066392adb623dcd5e0e2ddfb27bfa84dcfd32062ffacc7a6287a6b4e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106621);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-4947");
  script_bugtraq_id(102852);
  script_xref(name:"VMSA", value:"2018-0006");

  script_name(english:"VMware vRealize Automation Deserialization Vulnerability (VMSA-2018-0006)");
  script_summary(english:"Checks the version of VMware vRealize Automation.");

  script_set_attribute(attribute:"synopsis", value:
"A device management application running on the remote host is affected
by a deserialization vulnerability .");
  script_set_attribute(attribute:"description", value:
"The VMware vRealize Automation application running on the remote host
is version 7.2 or 7.3 and is missing security patches indicated in the
vendor advisory. It is, therefore, affected by a deserialization
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2018-0006.html");
  script_set_attribute(attribute:"solution", value:
"Apply the fixes as indicated in the vendor advisory to VMware
vRealize Automation.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_automation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/VMware vRealize Automation/Version", "installed_sw/VMware vRealize Automation");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("telnet_func.inc");

app = "VMware vRealize Automation";
flag = FALSE;

version = get_kb_item_or_exit("Host/" + app + "/Version");
port = 0;

if ( islocalhost() )
{
  if ( ! defined_func("pread")  ) exit(0);
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (! sock_g) exit(0);
    info_t = INFO_SSH;
}

if (version =~ "^7\.2(\.[0-9]+)?$")
{
  buf = info_send_cmd(cmd: "cat /etc/xenon/patch.info");
  if (empty_or_null(buf) || "7.2-HF2" >!< buf)
  {
    flag = TRUE;
    kb = "KB52320";
  }
}
else if (version =~ "^7\.3(\.[0-9]+)?$")
{
  buf = info_send_cmd(cmd: "cat /etc/xenon/patch.info");
  if (empty_or_null(buf) || "7.3-HF3" >!< buf)
  {
    flag = TRUE;
    kb = "KB52316";
  }
  # The appliance doesn't handle successive commands very well so we need to sleep
  sleep(1);
  buf = info_send_cmd(cmd:"rpm -qi health-broker-service-host | grep -F 'Version'");
  if (!empty_or_null(buf)) ver1 = pregmatch(pattern: "^Version\s+:\s+([0-9\.]+)", string:buf);
  sleep(1);
  buf = info_send_cmd(cmd:"rpm -qi vra-tests-host | grep -F 'Version'");
  if (!empty_or_null(buf)) ver2 = pregmatch(pattern: "^Version\s+:\s+([0-9\.]+)", string:buf);
  if (!empty_or_null(ver1) && !empty_or_null(ver1[1])) ver1 = ver1[1];
  if (!empty_or_null(ver2) && !empty_or_null(ver2[1])) ver2 = ver2[1];

  if (!empty_or_null(ver1) && !empty_or_null(ver2) && (ver_compare(ver:ver1, fix:"1.0.4", strict:FALSE) < 0 || ver_compare(ver:ver2, fix:"1.0.4", strict:FALSE) < 0))
  {
    flag = TRUE;
    if (!empty_or_null(kb)) kb = kb + ", KB52326";
    else kb = "KB52326";
  }
}

if(info_t == INFO_SSH) ssh_close_connection();

if (flag == TRUE)
{
  report = report_items_str(
    report_items:make_array(
      "Installed version", version,
      "KB(s)", kb
    ),
    ordered_fields:make_list("Installed version", "KB(s)")
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
