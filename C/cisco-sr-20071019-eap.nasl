#TRUSTED 3fc36fb57a25737856c8d905eed5c310fabee8e8ddc8a062d9ec9330e26d9c51b17c5d3b4bb9c18e128cb7b309bf60d436c2e51d5d4c590f28c492b5a5c0b49d5390ba32de628ab7fa78ef3f5c05bfae865fc03ecd6f99d0fbbadd70b6dbccc9941cb73aef45a85fd01a48706373eb35abbef6e27cc7b6ec98115d4f73f509c51b9725cf2865233ef402488c7dbf7c300600a1c37441fe3ebe8dd505ae5556c5f1c61dde84edf8dabf0035def38eb36f2da7384c6fb8d5170fbbd58c1523dde9b654c5828587c03e5a5c4ccebc912ce432b9793c4f61afa7d97390ac565f29f911e42d9b79461c186fee526760107cf182564f263164bc2b14ee6c4e33d67ebd25262912ec33181c39c9c45854ee59f7b988f4c99150628368809abe23d525b0cfc06a3bbdec63f4785f53611e522255290075a49cb68ce934d1bb8f1e600c2fa5be1d14582476b77c51f9c44e6d27a8955d512023764c281927fd8b554d04c465ddc4b2f7015161e97a11f22a6dae86ae0dbc02cc266aabebc3d06fdc93d3340fe294c09ae7738b6b7331ce97f325f1ae19815e1c5d90375cdd25f744baf6788a27fa5dda6c7984f45bf2c8e21f9fd1937d75665de536c0ede410e407c95eae5afe6c34a35638f3d14fb9cbb93812cb263876e46ea07a6d1b317afa6b88272ffadb5872e02bcd93b2274f1843be1225b1d38f9208bcc28b963586a9b74456ec
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68991);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2007-5651");
  script_bugtraq_id(26139);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsb45696");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsj56438");
  script_xref(name:"CISCO-SR", value:"cisco-sr-20071019-eap");

  script_name(english:"Cisco IOS Extensible Authentication Protocol Vulnerability (cisco-sr-20071019-eap)");
  script_summary(english:"Checks IOS version and running config");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco IOS running on the remote host has a denial of
service vulnerability.  The Extensible Authentication Protocol (EAP)
implementation does not properly process EAP packets, which could cause
the device to crash.  A remote, unauthenticated attacker could exploit
this to execute arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.cr0.org/paper/hacklu2007-final.pdf");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20071019-eap
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c4e5585");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in the Cisco Security Response
cisco-sr-20071019-eap."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-5651");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
vuln = 0;

if (deprecated_version(version, "12.3JA")) vuln++;
if (check_release(version:version, patched:make_list("12.4(10b)JA"))) vuln++;
if (deprecated_version(version, "12.3JEA")) vuln++;
if (deprecated_version(version, "12.3JEB")) vuln++;
if (check_release(version:version, patched:make_list("12.3(8)JEC"))) vuln++;
if (deprecated_version(version, "12.4JX")) vuln++;
if (check_release(version:version, patched:make_list("12.4(5)XW"))) vuln++;  # the advisory says 12.4.XW5, i assume that is 12.4(5)XW
if (check_release(version:version, patched:make_list("12.1(27b)E2"))) vuln++;
if (check_release(version:version, patched:make_list("12.1(22)EA6"))) vuln++;
if (check_release(version:version, patched:make_list("12.1(26)EB2"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(18)EW6"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(18)S13"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(18)SXF9"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(18)ZY1"))) vuln++; # the advisory says 12.2.18-ZY1
if (check_release(version:version, patched:make_list("12.2(20)S13"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(25)EWA4"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(25)EX"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(25)FX"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(25)SED"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(25)SG"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(31)SB6"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(33)SRA4"))) vuln++;

if (!vuln)
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS', version);

override = 0;

if (
  get_kb_item("Host/local_checks_enabled") &&
  running_config = get_kb_item("Secret/Host/Cisco/show_running")
)
{
  config_vuln = 0;

  # two requirements for CSCsj56438 to be present on APS and 1310 Wireless Bridges:
  #
  # 1) The device must be running IOS in autonomous mode:
  #    "Access Points and 1310 Wireless Bridges running in LWAPP mode are not affected.
  #     Access Points in autonomous mode will have -K9W7- in the image names,
  #     while Access Points in LWAPP mode will have -K9W8- in their name."
  #
  # 2) "To determine if EAP is enabled on the Access Point, log into the device and issue the show running-config CLI
  #     command. If the output contains the
  #
  #      authentication open eap 'method_name'
  #    or
  #      authentication network-eap 'method_name'
  #
  #    then the device is vulnerable."
  feature_set = get_kb_item("Host/Cisco/IOS/FeatureSet");

  if (
    feature_set == 'K9W7' &&
    ('authentication open eap' >< running_config || 'authentication network-eap' >< running_config)
  )
  {
    config_vuln++;
  }

  # Two possible vulnerable configurations for CSCsj56438 on Catalyst 6500 Series and 7600 Series Wireless LAN
  # Services Module.  The device is vulnerable if the output of "show running-config" contains either of the following:
  #
  # 1) wlccp authentication-server client <any | eap | leap> <list_name>
  #
  # 2) wlccp authentication-server infrastructure <list>
  if (
    running_config =~ 'wlccp authentication-server client (any|eap|leap)' ||
    'wlccp authentication-server infrastructure' >< running_config
  )
  {
    config_vuln++;
  }

  # IOS switches are vulnerable to CSCsb45696 if the output of "show running-config" contains either of the following:
  #
  # dot1x pae authenticator
  # dot1x pae both
  if ('dot1x pae authenticator' >< running_config || 'dot1x pae both' >< running_config )
  {
    config_vuln++;
  }

  # There are configuration checks for CSCsc55249 (CatOS) but this plugin currently doesn't support authenticated
  # scans of CatOS devices

  if (!config_vuln)
    exit(0, 'The remote host is not affected.  The IOS version is unpatched, but the device is not using a vulnerable configuration.');
}

security_hole(port:0, extra:cisco_caveat(override));

