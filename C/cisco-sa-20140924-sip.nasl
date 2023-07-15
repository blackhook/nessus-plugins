#TRUSTED 605c57695ad3a4eb11b6efc555baa03d308d036993add3e56682157826716ef3c80695a45b142924e2b7ba1a4bfdfd854f84cd99fc2a63bb91bd331e46c06598d55efefc0cefec9ce5e92e0218655f81d1642655243d04e45348b5387e4677425ebd733d0da2f51c3da7e10fffa8db43ce2e9eb66dd7fe770df7ffc2eb61fae0492ad3bde7ab26f66805da703b6cf1c1c7a225ba717da4d689402bfe80128d14d2277d95441af1f266c2b8601f4f2dcd348cf0b263942c921ccc5466bbeb0ca1518ddaac508b8ab166f12b306e40d9798af242f5b995c74670bc634e53c12929aab16876297753bd3e9b1dbf65b5a309237f6b0a4bfce272bbd0cf37e7d777574d0c9ff09d72762d2ddaf0a7f83f42bb20cd9c6e69a3119d3f272b8f5bbfe7c8ad4e3fd52d71a085b67e2d18446b3e0809ec58e93360f6cf7e0931e1f83fc23efd063d519df1f74f879d8693325e174cd4c8a3574a94c4c573c5daea294dac6461fc23d646a847463958b13f83d76f653c55591dc65ca429c80a012fc6edda599d98e0f5198093d119720d16b98319cdf1c51e21051cc50e55fecf8e5135ff1630ec4cdca053393655a21e1dd40df745e4c5757d2e81999d7a8247328dd8ad585814a62d836e417c4bd3b3d680d7d6ba6d8b0e324ee56106bc3b763f02960279fc8a5f7f338febe10e42f7a52168693e50f8d230bd2b8ebbf09ba3cf32c15b36
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78037);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3360");
  script_bugtraq_id(70141);
  script_xref(name:"CISCO-BUG-ID", value:"CSCul46586");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-sip");

  script_name(english:"Cisco IOS Software SIP DoS (cisco-sa-20140924-sip)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a vulnerability in the
Session Initiation Protocol (SIP) implementation due to improper
handling of SIP messages. A remote attacker can exploit this issue by
sending specially crafted SIP messages to cause the device to reload.

Note that this issue only affects hosts configured to process SIP
messages. SIP is not enabled by default on newer IOS versions.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00b78a3e");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35611");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35259");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul46586");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-sip.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

app = "Cisco IOS";
cbi = "CSCul46586";
fixed_ver = NULL;

#12.4GC
if (ver == "12.4(22)GC1" || ver == "12.4(22)GC1a" || ver == "12.4(24)GC1" || ver == "12.4(24)GC3" || ver == "12.4(24)GC3a" || ver == "12.4(24)GC4" || ver == "12.4(24)GC5")
  fixed_ver = "Refer to the vendor.";
#12.4T
else if (ver == "12.4(22)T" || ver == "12.4(22)T1" || ver == "12.4(22)T2" || ver == "12.4(22)T3" || ver == "12.4(22)T4" || ver == "12.4(22)T5" || ver == "12.4(24)T" || ver == "12.4(24)T1" || ver == "12.4(24)T10" || ver == "12.4(24)T11" || ver == "12.4(24)T2" || ver == "12.4(24)T3" || ver == "12.4(24)T4" || ver == "12.4(24)T5" || ver == "12.4(24)T6" || ver == "12.4(24)T7" || ver == "12.4(24)T8" || ver == "12.4(24)T9")
  fixed_ver = "12.4(24)T3a, 12.4(24)T4a, or 12.4(24)T12";
#12.4YA
else if (ver == "12.4(20)YA" || ver == "12.4(20)YA1" || ver == "12.4(20)YA2" || ver == "12.4(20)YA3")
  fixed_ver = "12.4(24)T3a, 12.4(24)T4a, or 12.4(24)T12";
#12.4YB
else if (ver == "12.4(22)YB" || ver == "12.4(22)YB1" || ver == "12.4(22)YB2" || ver == "12.4(22)YB3" || ver == "12.4(22)YB4" || ver == "12.4(22)YB5" || ver == "12.4(22)YB6" || ver == "12.4(22)YB7" || ver == "12.4(22)YB8")
  fixed_ver = "Refer to the vendor.";
#15.0M
else if (ver == "15.0(1)M" || ver == "15.0(1)M1" || ver == "15.0(1)M10" || ver == "15.0(1)M2" || ver == "15.0(1)M3" || ver == "15.0(1)M4" || ver == "15.0(1)M5" || ver == "15.0(1)M6" || ver == "15.0(1)M7" || ver == "15.0(1)M8" || ver == "15.0(1)M9")
  fixed_ver = "15.0(1)M6a";
#15.0XA
else if (ver == "15.0(1)XA" || ver == "15.0(1)XA1" || ver == "15.0(1)XA2" || ver == "15.0(1)XA3" || ver == "15.0(1)XA4" || ver == "15.0(1)XA5")
  fixed_ver = "15.1(4)M9";
#15.1GC
else if (ver == "15.1(2)GC" || ver == "15.1(2)GC1" || ver == "15.1(2)GC2" || ver == "15.1(4)GC" || ver == "15.1(4)GC1")
  fixed_ver = "15.1(4)GC2";
#15.1M
else if (ver == "15.1(4)M" || ver == "15.1(4)M0a" || ver == "15.1(4)M0b" || ver == "15.1(4)M1" || ver == "15.1(4)M2" || ver == "15.1(4)M3" || ver == "15.1(4)M3a" || ver == "15.1(4)M4" || ver == "15.1(4)M5" || ver == "15.1(4)M6" || ver == "15.1(4)M7" || ver == "15.1(4)M8")
  fixed_ver = "15.1(4)M9";
#15.1T
else if (ver == "15.1(1)T" || ver == "15.1(1)T1" || ver == "15.1(1)T2" || ver == "15.1(1)T3" || ver == "15.1(1)T4" || ver == "15.1(1)T5" || ver == "15.1(2)T" || ver == "15.1(2)T0a" || ver == "15.1(2)T1" || ver == "15.1(2)T2" || ver == "15.1(2)T2a" || ver == "15.1(2)T3" || ver == "15.1(2)T4" || ver == "15.1(2)T5" || ver == "15.1(3)T" || ver == "15.1(3)T1" || ver == "15.1(3)T2" || ver == "15.1(3)T3" || ver == "15.1(3)T4")
  fixed_ver = "15.1(4)M9";
#15.1XB
else if (ver == "15.1(1)XB" || ver == "15.1(1)XB1" || ver == "15.1(1)XB2" || ver == "15.1(1)XB3" || ver == "15.1(4)XB4" || ver == "15.1(4)XB5" || ver == "15.1(4)XB5a" || ver == "15.1(4)XB6" || ver == "15.1(4)XB7" || ver == "15.1(4)XB8" || ver == "15.1(4)XB8a")
  fixed_ver = "15.1(4)M9";
#15.2GC
else if (ver == "15.2(1)GC" || ver == "15.2(1)GC1" || ver == "15.2(1)GC2" || ver == "15.2(2)GC" || ver == "15.2(3)GC" || ver == "15.2(3)GC1" || ver == "15.2(4)GC" || ver == "15.2(4)GC1" || ver == "15.2(4)GC2")
  fixed_ver = "15.2(4)M7";
#15.2GCA
else if (ver == "15.2(3)GCA" || ver == "15.2(3)GCA1")
  fixed_ver = "15.4(1)T2 or 15.4(2)T";
#15.2M
else if (ver == "15.2(4)M" || ver == "15.2(4)M1" || ver == "15.2(4)M2" || ver == "15.2(4)M3" || ver == "15.2(4)M4" || ver == "15.2(4)M5" || ver == "15.2(4)M6" || ver == "15.2(4)M6b")
  fixed_ver = "15.2(4)M7";
#15.2T
else if (ver == "15.2(1)T" || ver == "15.2(1)T1" || ver == "15.2(1)T2" || ver == "15.2(1)T3" || ver == "15.2(1)T3a" || ver == "15.2(1)T4" || ver == "15.2(2)T" || ver == "15.2(2)T1" || ver == "15.2(2)T2" || ver == "15.2(2)T3" || ver == "15.2(2)T4" || ver == "15.2(3)T" || ver == "15.2(3)T1" || ver == "15.2(3)T2" || ver == "15.2(3)T3" || ver == "15.2(3)T4")
  fixed_ver = "15.2(4)M7";
#15.2XB
else if (ver == "15.2(4)XB10")
  fixed_ver = "15.2(4)XB11";
#15.3M
else if (ver == "15.3(3)M" || ver == "15.3(3)M1" || ver == "15.3(3)M2" || ver == "15.3(3)M3")
  fixed_ver = "15.3(3)M4";
#15.3T
else if (ver == "15.3(1)T" || ver == "15.3(1)T1" || ver == "15.3(1)T2" || ver == "15.3(1)T3" || ver == "15.3(1)T4" || ver == "15.3(2)T" || ver == "15.3(2)T1" || ver == "15.3(2)T2" || ver == "15.3(2)T3")
  fixed_ver = "15.3(2)T4";
#15.4CG
else if (ver == "15.4(1)CG")
  fixed_ver = "15.4(1)CG1 or 15.4(2)CG";
#15.4T
else if (ver == "15.4(1)T" || ver == "15.4(1)T1")
  fixed_ver = "15.4(1)T2 or 15.4(2)T";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

# SIP check
# nb SIP can listen on TCP or UDP
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # SIP UDP listening check
  # Example:
  # 17     0.0.0.0             0 --any--          5060   0   0    11   0
  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*(?:\S+\s+){4}5060\s+", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override)
  {
    # SIP TCP listening check
    # Example:
    # 7F1277405E20  0.0.0.0.5061               *.*                         LISTEN
    # 7F127BBE20D8  0.0.0.0.5060               *.*                         LISTEN
    buf = cisco_command_kb_item("Host/Cisco/Config/show_tcp_brief_all", "show tcp brief all");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^\S+\s+\S+(506[01])\s+", string:buf)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because SIP is not listening on TCP or UDP.");
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
