#TRUSTED 51cd953e235f07f468f432be296a2a604d9ddf375c94654161798620e1f0e286ef5dc63840e10fc209b1f14cee516f189967a462ffd959afc2d309e1db797a727b5d34074035a5794b66a4ccd56ff878b0fb0869c505a87593f7c20c769d7c9e1fedd74367519892cf846b0e8f781207fd6096d6465d45107b573c3b3ce620eba6cf6fade9d02529cb8c7c25bd2b308b3e75b08a245a8a3993130ed39824d67c3530230cc7e9b2bee31e71ecb81a6a2f3a7dd9965fa13733d188097c6decdcfdce136190a508b91bbc4943f7201ecca2a8e13f743075ff1cacac77b728aaf8a531b30d5dd168f6ba7683bf66bbfd592b729b39d905132027b392095cd4dfdb8338cd48a4f4e6676d0a7dcc8c8df820c61424b4d6dd9459d3b5f8e7e4627aa3f9bf153af62ec7ff2c07126186ce70a9cf241200233067b3601bec29cc211be66d099b6b5255d400fb2ae8ee13e6f138a43cdcf2db5338678137f9f47a25983761e8920fa137696df396a43c07c954597f5d6e7bbd8ff7d3778a7f7eb7888584edbfb26b9e5bae2392e32a82ab46774df1707b72d2955340697e13359618bf5dc76381e7dc64b27d9df0c5937bb3eb0b11de1fd4b53f6b57ebfc25b03ea7f976f06801e58946993f60fadb95d5d0cf2a3d4a082292b79acbf7945281ff56a606d49862d1873ccd7148e8557f1b180352686ff40c2fe75ca70ef6efcb1ba7ca5ecf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69471);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/29");

  script_cve_id("CVE-2013-0137");
  script_bugtraq_id(60810);
  script_xref(name:"CERT", value:"662676");

  script_name(english:"Multiple Vendors EAS Authentication Bypass");
  script_summary(english:"Checks the authorized_keys2.dasdec file for the presence of the compromised key");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication bypass 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote EAS device permits root login using an SSH key with a 
publicly available private key. The private key was included in 
older copies of Monroe Electronics and Digital Alert Systems firmware.
A remote attacker with access to the private key can bypass 
authentication of the root user.");
  script_set_attribute(attribute:"solution", value:"Update to firmware version 2.0-2 or higher.");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/662676/");
  # https://web.archive.org/web/20130712221439/http://www.informationweek.com/security/vulnerabilities/zombie-apocalypse-broadcast-hoax-explain/240157934
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?637f824e");
  # https://arstechnica.com/information-technology/2013/07/we-interrupt-this-program-to-warn-the-emergency-alert-system-is-hackable/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbb8fb12");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:monroe_electronics:r189_one-net_eas");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:digital_alert_systems:dasdec_eas");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("ssh_func.inc");


if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

keygen_command = "test -f /root/.ssh/authorized_keys2.dasdec && ssh-keygen -l -f /root/.ssh/authorized_keys2.dasdec";
line_count_command = 'test -f /root/.ssh/authorized_keys2.dasdec && wc -l /root/.ssh/authorized_keys2.dasdec';
keygen_expected = "1024 0c:89:49:f7:62:d2:98:f0:27:75:ad:e9:72:2c:68:c3 ";

if ("Linux" >!< get_kb_item_or_exit("Host/uname"))
  audit(AUDIT_OS_NOT, "Linux");

ret = ssh_open_connection();
if (!ret)
  audit(AUDIT_SVC_FAIL, "SSH", kb_ssh_transport());

keygen_output = ssh_cmd(cmd:keygen_command, nosh:TRUE, nosudo:FALSE);

if (keygen_expected >< keygen_output)
{
  ssh_close_connection();
  
  vuln_report = NULL;
  if (report_verbosity > 0)
  {
    vuln_report = '\nFound the RSA public key with fingerprint "0c:89:49:f7:62:d2:98:f0:27:75:ad:e9:72:2c:68:c3" in the authorized keys file.\n';
  }

  security_hole(port:kb_ssh_transport(), extra:vuln_report);
  exit(0);
}

if (report_paranoia > 1)
{
  line_count_output = ssh_cmd(cmd:line_count_command, nosh:TRUE, nosudo:FALSE);
  ssh_close_connection();

  matches = eregmatch(pattern:"^([0-9]+) ", string:line_count_output);
  if (isnull(matches) || isnull(matches[1]))
    # This is set to 1 arbitrarily. It could just as well be set to 0.
    # It is set to something <=1 to pass the (... && line_count > 1) check below.
    # If we can't get a number out of the wc -l output, we can't advise the user to manually audit.
    line_count = 1;
  else
    line_count = int(matches[1]);

  if (line_count > 1)
  {
    audit_msg =
      " Note that Nessus checked only the first key in the authorized_keys2.dasdec file,
      yet the file has more than one line. Please manually audit this file.";
    exit(0, audit_msg);
  }
  else
    audit(AUDIT_HOST_NOT, "an affected EAS device");
}
else
{
  ssh_close_connection();
  audit(AUDIT_HOST_NOT, "an affected EAS device");
}
