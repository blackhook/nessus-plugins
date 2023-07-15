#TRUSTED 0102e7ade2f7d80ac14c4280273b80883994a354aedc4ec8579a7339a39191bbe7af40281fa5dfd528b6e066b6a0fab2fd315d501ce9398640392d0ff98c4d939c32846f9fe9a41595443b2f7aa69d97cd8ec52f83e4e9ba478de0d241f00215c7d86fb91327a0aaf3bdcdc0f475fa974b63e5d9b9cc037b987d7640ca5211dc8a3697a2b054aa446754611fa85e6d4c60f8d4c9ce05736a210be9792dce87d356e262cc154c65ee0c3df9e8f2632cf38192bb3c90c68ce331e3f5796fe4428f04809a95d78e986c30a6ce31bf6a05cb55184ec6fd6b96412f360e2fa37b2ff996cc91d9805d857fd8c395e2b315659352b057ce5da7474c0926a9a5810728268b7dcd6c6478fecb95d7174f2f12b3589560c98a058d4406fc2d7a36b38fccc950a4983b538df117981a80755319527f99159a89261b6139945b53ec567907c388d5bba4d89a927d69cf2f661c381dbd7e86720ed3a9c848ac1a0fc5abb0cf1839c4d341dc0398af11325ae3ff0a3ccc0c0aa86f4142204ffd5880fa6247643e86d0e975faec305b3c51aa95dab98c9d78ef1a1e1a255bb3efc25d86f83f57a73f37abb30fc4c64d986615ad42c84df320068284a3d1f6e8f5e71235993ca9b98b842958e4cda5929512d580df1704526121cd6c45d84628d52f20d0cb7b922de0f1ca08dc679590e48dde68ef097c32e4d5867c07f6e8ba6ac4d18fe20d9b42
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90358);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-1349");
  script_xref(name:"TRA", value:"TRA-2016-04");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv45410");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-smi");

  script_name(english:"Cisco IOS Smart Install Packet Image List Parameter Handling DoS (cisco-sa-20160323-smi)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Smart Install client feature due to improper handling of image
list parameters. An unauthenticated, remote attacker can exploit this
issue, via crafted Smart Install packets, to cause the device to
reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14b003f9");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-04");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuv45410. Alternatively, disable the Smart Install feature per the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1349");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == '12.2(35)EX' ) flag++;
if ( ver == '12.2(35)EX1' ) flag++;
if ( ver == '12.2(35)EX2' ) flag++;
if ( ver == '12.2(37)EX' ) flag++;
if ( ver == '12.2(40)EX' ) flag++;
if ( ver == '12.2(40)EX1' ) flag++;
if ( ver == '12.2(40)EX2' ) flag++;
if ( ver == '12.2(40)EX3' ) flag++;
if ( ver == '12.2(44)EX' ) flag++;
if ( ver == '12.2(44)EX1' ) flag++;
if ( ver == '12.2(46)EX' ) flag++;
if ( ver == '12.2(52)EX' ) flag++;
if ( ver == '12.2(52)EX1' ) flag++;
if ( ver == '12.2(53)EX' ) flag++;
if ( ver == '12.2(55)EX' ) flag++;
if ( ver == '12.2(55)EX1' ) flag++;
if ( ver == '12.2(55)EX2' ) flag++;
if ( ver == '12.2(55)EX3' ) flag++;
if ( ver == '12.2(58)EX' ) flag++;
if ( ver == '12.2(37)EY' ) flag++;
if ( ver == '12.2(44)EY' ) flag++;
if ( ver == '12.2(46)EY' ) flag++;
if ( ver == '12.2(53)EY' ) flag++;
if ( ver == '12.2(55)EY' ) flag++;
if ( ver == '12.2(58)EY' ) flag++;
if ( ver == '12.2(58)EY1' ) flag++;
if ( ver == '12.2(58)EY2' ) flag++;
if ( ver == '12.2(53)EZ' ) flag++;
if ( ver == '12.2(55)EZ' ) flag++;
if ( ver == '12.2(58)EZ' ) flag++;
if ( ver == '12.2(60)EZ' ) flag++;
if ( ver == '12.2(60)EZ1' ) flag++;
if ( ver == '12.2(60)EZ2' ) flag++;
if ( ver == '12.2(60)EZ3' ) flag++;
if ( ver == '12.2(60)EZ4' ) flag++;
if ( ver == '12.2(60)EZ5' ) flag++;
if ( ver == '12.2(60)EZ6' ) flag++;
if ( ver == '12.2(60)EZ7' ) flag++;
if ( ver == '12.2(60)EZ8' ) flag++;
if ( ver == '12.2(25)FZ' ) flag++;
if ( ver == '12.2(35)SE' ) flag++;
if ( ver == '12.2(35)SE1' ) flag++;
if ( ver == '12.2(35)SE2' ) flag++;
if ( ver == '12.2(35)SE3' ) flag++;
if ( ver == '12.2(35)SE4' ) flag++;
if ( ver == '12.2(35)SE5' ) flag++;
if ( ver == '12.2(37)SE' ) flag++;
if ( ver == '12.2(37)SE1' ) flag++;
if ( ver == '12.2(40)SE' ) flag++;
if ( ver == '12.2(40)SE1' ) flag++;
if ( ver == '12.2(40)SE2' ) flag++;
if ( ver == '12.2(44)SE' ) flag++;
if ( ver == '12.2(44)SE1' ) flag++;
if ( ver == '12.2(44)SE2' ) flag++;
if ( ver == '12.2(44)SE3' ) flag++;
if ( ver == '12.2(44)SE4' ) flag++;
if ( ver == '12.2(44)SE5' ) flag++;
if ( ver == '12.2(44)SE6' ) flag++;
if ( ver == '12.2(46)SE' ) flag++;
if ( ver == '12.2(46)SE1' ) flag++;
if ( ver == '12.2(46)SE2' ) flag++;
if ( ver == '12.2(50)SE' ) flag++;
if ( ver == '12.2(50)SE1' ) flag++;
if ( ver == '12.2(50)SE2' ) flag++;
if ( ver == '12.2(50)SE3' ) flag++;
if ( ver == '12.2(50)SE4' ) flag++;
if ( ver == '12.2(50)SE5' ) flag++;
if ( ver == '12.2(52)SE' ) flag++;
if ( ver == '12.2(52)SE1' ) flag++;
if ( ver == '12.2(53)SE' ) flag++;
if ( ver == '12.2(53)SE1' ) flag++;
if ( ver == '12.2(53)SE2' ) flag++;
if ( ver == '12.2(54)SE' ) flag++;
if ( ver == '12.2(55)SE' ) flag++;
if ( ver == '12.2(55)SE1' ) flag++;
if ( ver == '12.2(55)SE10' ) flag++;
if ( ver == '12.2(55)SE2' ) flag++;
if ( ver == '12.2(55)SE3' ) flag++;
if ( ver == '12.2(55)SE4' ) flag++;
if ( ver == '12.2(55)SE5' ) flag++;
if ( ver == '12.2(55)SE6' ) flag++;
if ( ver == '12.2(55)SE7' ) flag++;
if ( ver == '12.2(55)SE8' ) flag++;
if ( ver == '12.2(55)SE9' ) flag++;
if ( ver == '12.2(58)SE' ) flag++;
if ( ver == '12.2(58)SE1' ) flag++;
if ( ver == '12.2(58)SE2' ) flag++;
if ( ver == '12.2(25)SED' ) flag++;
if ( ver == '12.2(25)SED1' ) flag++;
if ( ver == '12.2(25)SEE' ) flag++;
if ( ver == '12.2(25)SEE1' ) flag++;
if ( ver == '12.2(25)SEE2' ) flag++;
if ( ver == '12.2(25)SEE3' ) flag++;
if ( ver == '12.2(25)SEE4' ) flag++;
if ( ver == '12.2(25)SEF1' ) flag++;
if ( ver == '12.2(25)SEF2' ) flag++;
if ( ver == '12.2(25)SEF3' ) flag++;
if ( ver == '12.2(25)SEG' ) flag++;
if ( ver == '12.2(25)SEG1' ) flag++;
if ( ver == '12.2(25)SEG2' ) flag++;
if ( ver == '12.2(25)SEG3' ) flag++;
if ( ver == '12.2(25)SEG4' ) flag++;
if ( ver == '12.2(25)SEG5' ) flag++;
if ( ver == '12.2(25)SEG6' ) flag++;
if ( ver == '15.0(2)EB' ) flag++;
if ( ver == '15.0(2)EC' ) flag++;
if ( ver == '15.0(2)ED' ) flag++;
if ( ver == '15.0(2)ED1' ) flag++;
if ( ver == '15.0(2)EH' ) flag++;
if ( ver == '15.0(2)EJ' ) flag++;
if ( ver == '15.0(2)EJ1' ) flag++;
if ( ver == '15.0(2)EK' ) flag++;
if ( ver == '15.0(2)EK1' ) flag++;
if ( ver == '15.0(1)EX' ) flag++;
if ( ver == '15.0(2)EX' ) flag++;
if ( ver == '15.0(2)EX1' ) flag++;
if ( ver == '15.0(2)EX2' ) flag++;
if ( ver == '15.0(2)EX3' ) flag++;
if ( ver == '15.0(2)EX4' ) flag++;
if ( ver == '15.0(2)EX5' ) flag++;
if ( ver == '15.0(2)EX8' ) flag++;
if ( ver == '15.0(2a)EX5' ) flag++;
if ( ver == '15.0(1)EY' ) flag++;
if ( ver == '15.0(1)EY1' ) flag++;
if ( ver == '15.0(1)EY2' ) flag++;
if ( ver == '15.0(2)EY' ) flag++;
if ( ver == '15.0(2)EY1' ) flag++;
if ( ver == '15.0(2)EY2' ) flag++;
if ( ver == '15.0(2)EY3' ) flag++;
if ( ver == '15.0(2)EZ' ) flag++;
if ( ver == '15.0(1)SE' ) flag++;
if ( ver == '15.0(1)SE1' ) flag++;
if ( ver == '15.0(1)SE2' ) flag++;
if ( ver == '15.0(1)SE3' ) flag++;
if ( ver == '15.0(2)SE' ) flag++;
if ( ver == '15.0(2)SE1' ) flag++;
if ( ver == '15.0(2)SE2' ) flag++;
if ( ver == '15.0(2)SE3' ) flag++;
if ( ver == '15.0(2)SE4' ) flag++;
if ( ver == '15.0(2)SE5' ) flag++;
if ( ver == '15.0(2)SE6' ) flag++;
if ( ver == '15.0(2)SE7' ) flag++;
if ( ver == '15.2(1)E' ) flag++;
if ( ver == '15.2(1)E1' ) flag++;
if ( ver == '15.2(1)E2' ) flag++;
if ( ver == '15.2(1)E3' ) flag++;
if ( ver == '15.2(2)E' ) flag++;
if ( ver == '15.2(2)E1' ) flag++;
if ( ver == '15.2(2)E2' ) flag++;
if ( ver == '15.2(2)E3' ) flag++;
if ( ver == '15.2(2a)E1' ) flag++;
if ( ver == '15.2(2a)E2' ) flag++;
if ( ver == '15.2(3)E' ) flag++;
if ( ver == '15.2(3)E1' ) flag++;
if ( ver == '15.2(3)E2' ) flag++;
if ( ver == '15.2(3a)E' ) flag++;
if ( ver == '15.2(3m)E2' ) flag++;
if ( ver == '15.2(3m)E3' ) flag++;
if ( ver == '15.2(2)EB' ) flag++;
if ( ver == '15.2(2)EB1' ) flag++;
if ( ver == '15.2(1)EY' ) flag++;
if ( ver == '15.2(2)EA1' ) flag++;
if ( ver == '15.2(2)EA2' ) flag++;
if ( ver == '15.2(3)EA' ) flag++;

# Check for Smart Install client feature
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
  if (check_cisco_result(buf))
  {
    if ( (preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient", string:buf)) &&
         (!preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient\s+\(SmartInstall disabled\)", string:buf)) ) { flag = 1; }
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
      '\n  Cisco bug ID      : CSCuv45410' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
