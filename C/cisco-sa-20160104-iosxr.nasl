#TRUSTED 6e3b801cea31fca85386bec3a8ac36e30b4d9403afde971f5ce52657eb857778e0f4a0c89bbcf9c0b4a47c7ab1ad039ec240af44cf8f87f994e1acd745951a24a1437ed3fa66f73230d18f8c24bcca9bbf582dc02df242455378556e95598a09965bd3221adc8df0d694a95feb1ad29a1a120ad1861525833afdf982ae8d9ff3710c6656d7124f5df9f0f65f7bbf46ae389e549c0b2ffae369c27c7bc288be0e8d8eab2251bd39f2ed3fc77a2fd65a80e2b7ccae2eb08462c0bce44db430157dbde1267ac4f7dbfb9b2f58f7691cb24a4c6292aeec5c416d0f5ae8e390e23fd325523a6a35d2e212b8cf150e20c3f877998b7f4a5ad6eb98577a8780b8777889c3235d66af1e87c13981f6e7ce629645ec0c22de20acf77ff735f5f6e091b16b41acd2b69321a7d85684db978c169fc9e2a8f220ad34ca84ece866f73e907843bfd8b82d5f1e26b7ebbf77602d655587ebf88d794d7af9d4b80407fb4256ecb1302e7d164bcd6032a9889a3999be513ca8ae2165bbc2433ca80f8bbc2b2bcc36c429331ceb7de077160301c947f0c839a4fa7a65210e8c4506caf870af04eae7925ab5f21ee1140b3e5842b9669a9f77a88245eb18e662426a085dc5b57e6f4e1223475d51c3459801a3393687deeee7fd80b3a8d6a0a329574c587d9ca55d01fcc906ddb91b11f4750024a0212b6f29072b0474645fd202a1cabc1f7abaf3c5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87819);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2015-6432");
  script_bugtraq_id(79831);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw83486");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160104-iosxr");

  script_name(english:"Cisco IOS XR OSPF Link State Advertisement PCE DoS (cisco-sa-20160104-iosxr)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XR device is affected by a denial of service
vulnerability due to the number of Open Shortest Path First (OSPF)
Path Computation Elements (PCEs) configured for the OSPF Link State
Advertisement (LSA) opaque area update. An unauthenticated, remote
attacker can exploit this, via a specially crafted OSPF LSA update, to
cause a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160104-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6160ca1f");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20160104-iosxr.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6432");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

cbi = "CSCuw83486";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

if( version =~ '^4\\.[23]\\.0([^0-9]|$)' ) flag = 1;
if( version =~ '^5\\.[0-3]\\.0([^0-9]|$)' ) flag = 1;
if( version =~ '^5\\.2\\.[24]([^0-9]|$)' ) flag = 1;
if( version == '5.3.2' ) flag = 1;

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if( preg(multiline:TRUE, pattern:"^pce ", string:buf))
      flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : ' + cbi +
      '\n  Installed release : ' + version +
      '\n';

    security_warning(port:port, extra:report + cisco_caveat(override));
  }
  else security_warning(port:port, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
