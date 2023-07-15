#TRUSTED 68aabc253859aac7be40a7bb05e19d6b78b3f47d388ea679a53467600037181de7b6bac183015482d93c1cf3c76fecdf5a650e99bd682653c49d1fcb0694df64d0b49034cab010f8c33642247828e11d46854a8355878c555a831a8529dd28041d95b36f473492ee4ae38dfd8e42cfbee22f470da1abf99f9d79ef41586d73208dea3dda4a5965afb05547f5586319f0427624fff8271be01522a1fc1673f636d235705031a9ba19266a7efaa55b4fd494016c5e068739fd63dd3ff4d971b3588f62a9f4a16a70a5b8b515d9d146cc83bd3769a6f367ae6bd18f5176301bd7d445f237cbc019655bfb1437dd44dac5e2c30d34bc5a233796cc7c6e3a9de3e429e9483c49fc216117fc4ac3cb1924204632a779c75172cc26d0349d526ecc9ff1822db08e6ac37a7a7e6d5f7f2677b8f859847cf89003dc15e4d7a279117723a53d86fd3dfb5bdc15a7b52f6cb940093a906af1bd9b564644581b80f2f1cb3280dd76e04b7e11762498e721fd40a6ff0a6d5eb4131aa337cbf557484ad7da1e763373077854f065e868b3ec18e71aeedc2162a224e44167284b053380ed3ca19acd1c04cff87a063364c3570673d9ba16d30abc62ffbf8b87e7ba930f1cffc6982a33525eabf5f9eca8a396e973285346f5f947612d035b5ed12a088b5fab6fadf1e43d04ebc84b0b0a8226b08098e2dd7b5c4afe2540ad29eb886b78ddb1c63b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78033);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3355", "CVE-2014-3356");
  script_bugtraq_id(70130, 70135);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue22753");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug75942");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-metadata");

  script_name(english:"Cisco IOS Software Multiple IPv6 Metadata Flow Vulnerabilities (cisco-sa-20140924-metadata)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by two vulnerabilities in the
IPv6 metadata flow feature due to improper handling of RSVP packets. A
remote attacker can exploit this issue by sending specially crafted
RSVP flows to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-metadata
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?102835df");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35622");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35623");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCue22753");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCug75942");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-metadata.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

app = "Cisco IOS";
cbi = "CSCue22753 and CSCug75942";
fixed_ver = NULL;

#15.1SY
if (ver == "15.1(1)SY" || ver == "15.1(1)SY1")
  fixed_ver = "15.1(1)SY4 or 15.1(2)SY4";
else if (ver == "15.1(1)SY2" || ver == "15.1(1)SY3" || ver == "15.1(2)SY" || ver == "15.1(2)SY1" || ver == "15.1(2)SY2" || ver == "15.1(2)SY3")
{
  fixed_ver = "15.1(1)SY4 or 15.1(2)SY4";
  cbi = "CSCue22753";
}
#15.2GC
else if (ver == "15.2(1)GC" || ver == "15.2(1)GC1" || ver == "15.2(1)GC2" || ver == "15.2(2)GC" || ver == "15.2(3)GC" || ver == "15.2(3)GC1")
  fixed_ver = "15.2(4)M7";
else if (ver == "15.2(4)GC" || ver == "15.2(4)GC1" || ver == "15.2(4)GC2")
{
  fixed_ver = "15.2(4)M7";
  cbi = "CSCue22753";
}
#15.2GCA
else if (ver == "15.2(3)GCA" || ver == "15.2(3)GCA1")
  fixed_ver = "15.4(1)T";
#15.2M
else if (ver == "15.2(4)M" || ver == "15.2(4)M1" || ver == "15.2(4)M2" || ver == "15.2(4)M3")
  fixed_ver= "15.2(4)M7";
else if (ver == "15.2(4)M4" || ver == "15.2(4)M5" || ver == "15.2(4)M6" || ver == "15.2(4)M6b")
{
  fixed_ver = "15.2(4)M7";
  cbi = "CSCue22753";
}
#15.2S
else if (ver == "15.2(2)S" || ver == "15.2(2)S1" || ver == "15.2(4)S" || ver == "15.2(4)S1" || ver == "15.2(4)S2" || ver == "15.2(4)S3")
  fixed_ver = "15.2(2)S0a, 15.2(2)S2, 15.2(4)S0c, 15.2(4)S1c, 15.2(4)S2t, 15.2(4)S3a, or 15.2(4)S4";
#15.2T
else if (ver == "15.2(1)T" || ver == "15.2(1)T1" || ver == "15.2(1)T2" || ver == "15.2(1)T3" || ver == "15.2(1)T3a" || ver == "15.2(1)T4" || ver == "15.2(2)T" || ver == "15.2(2)T1" || ver == "15.2(2)T2" || ver == "15.2(2)T3" || ver == "15.2(2)T4" || ver == "15.2(3)T" || ver == "15.2(3)T1" || ver == "15.2(3)T2" || ver == "15.2(3)T3")
  fixed_ver = "15.2(4)M7";
else if (ver == "15.2(3)T4")
{
  fixed_ver = "15.2(4)M7";
  cbi = "CSCue22753";
}
#15.2XA
else if (ver == "15.2(3)XA")
  fixed_ver = "15.2(4)M7";
#15.2XB
else if (ver == "15.2(4)XB10")
  fixed_ver = "15.2(4)XB11";
#15.3M
else if (ver == "15.3(3)M" || ver == "15.3(3)M1" || ver == "15.3(3)M2" || ver == "15.3(3)M3")
{
  fixed_ver = "15.2(4)XB11";
  cbi = "CSCue22753";
}
#15.3S
else if (ver == "15.3(1)S" || ver == "15.3(1)S1" || ver == "15.3(2)S" || ver == "15.3(2)S0xa" || ver == "15.3(2)S1")
  fixed_ver = "15.3(1)S1e, 15.3(1)S2, 15.3(2)S1b, 15.3(2)S2, 15.3(3)S0b, 15.3(3)S1a, 15.3(3)S2a, or 15.3(3)S4";
else if (ver == "15.3(2)S0a" || ver == "15.3(3)S" || ver == "15.3(3)S1" || ver == "15.3(3)S2" || ver == "15.3(3)S3")
{
  fixed_ver = "15.3(1)S1e, 15.3(1)S2, 15.3(2)S1b, 15.3(2)S2, 15.3(3)S0b, 15.3(3)S1a, 15.3(3)S2a, or 15.3(3)S4";
  cbi = "CSCue22753";
}
#15.3T
else if (ver == "15.3(1)T" || ver == "15.3(1)T1" || ver == "15.3(2)T")
  fixed_ver = "15.3(2)T4";
else if (ver == "15.3(1)T2" || ver == "15.3(1)T3" || ver == "15.3(1)T4" || ver == "15.3(2)T1" || ver == "15.3(2)T2" || ver == "15.3(2)T3")
{
  fixed_ver = "15.3(2)T4";
  cbi = "CSCue22753";
}

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # metadata flow check
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*metadata flow$", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override)
  {
    # IPv6 metadata flow check
    buf = cisco_command_kb_item("Host/Cisco/Config/show_metadata_flow_table_ipv6", "show metadata flow table ipv6");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^Flow\s+Proto\s+DPort\s+SPort", string:buf)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the metadata flow feature is not enabled.");
}

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + 
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
