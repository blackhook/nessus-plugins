#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(17793);
  script_version("1.11");
  script_cvs_date("Date: 2018/11/15 20:50:20");

  script_cve_id("CVE-2001-1071");
  script_bugtraq_id(3412);
  script_xref(name:"CISCO-BUG-ID", value:"CSCdu09909");
  script_xref(name:"CERT", value:"139491");

  script_name(english:"Cisco IOS CDP Neighbor Announcement DoS");
  script_summary(english:"Checks IOS versions");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"There is a vulnerability in how Cisco routers handle CDP.  By sending
a large amount of CDP neighbor announcements it is possible to consume
all of the router's available memory.  

Note that a device would need to be configured to use CDP and an
attacker would need to be on the same segment as the target router in
order to exploit this vulnerability.");
  # https://web.archive.org/web/20040804055009/http://cisco.com/en/US/tech/tk648/tk362/technologies_tech_note09186a0080093ef0.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dddb2797");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2001/Oct/62");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch references in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2001-1071");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("cisco_func.inc");
include("audit.inc");

version = get_kb_item_or_exit('Host/Cisco/IOS/Version');

if (version == '12.0(10)')
  security_warning(0);
else if (version == '12.0(10a)')
  security_warning(0);
else if (version == '12.0(10r)S')
  security_warning(0);
else if (version == '12.0(10r)S1')
  security_warning(0);
else if (version == '12.0(10)S')
  security_warning(0);
else if (version == '12.0(10)S0418')
  security_warning(0);
else if (version == '12.0(10)S0426')
  security_warning(0);
else if (version == '12.0(10)S1')
  security_warning(0);
else if (version == '12.0(10)S2')
  security_warning(0);
else if (version == '12.0(10)S3')
  security_warning(0);
else if (version == '12.0(10)S3a')
  security_warning(0);
else if (version == '12.0(10)S3b')
  security_warning(0);
else if (version == '12.0(10)S4')
  security_warning(0);
else if (version == '12.0(10)S5')
  security_warning(0);
else if (version == '12.0(10)S6')
  security_warning(0);
else if (version == '12.0(10)S7')
  security_warning(0);
else if (version == '12.0(10)S8')
  security_warning(0);
else if (version == '12.0(10)SC')
  security_warning(0);
else if (version == '12.0(10)SC1')
  security_warning(0);
else if (version == '12.0(10)SL')
  security_warning(0);
else if (version == '12.0(10)ST')
  security_warning(0);
else if (version == '12.0(10)ST1')
  security_warning(0);
else if (version == '12.0(10)ST2')
  security_warning(0);
else if (version == '12.0(10)SX')
  security_warning(0);
else if (version == '12.0(11)')
  security_warning(0);
else if (version == '12.0(11a)')
  security_warning(0);
else if (version == '12.0(11)S')
  security_warning(0);
else if (version == '12.0(11)S1')
  security_warning(0);
else if (version == '12.0(11)S2')
  security_warning(0);
else if (version == '12.0(11)S3')
  security_warning(0);
else if (version == '12.0(11)S4')
  security_warning(0);
else if (version == '12.0(11)S5')
  security_warning(0);
else if (version == '12.0(11)S6')
  security_warning(0);
else if (version == '12.0(11)SC')
  security_warning(0);
else if (version == '12.0(11)SL')
  security_warning(0);
else if (version == '12.0(11)SL1')
  security_warning(0);
else if (version == '12.0(11)ST')
  security_warning(0);
else if (version == '12.0(11)ST1')
  security_warning(0);
else if (version == '12.0(11)ST2')
  security_warning(0);
else if (version == '12.0(11)ST3')
  security_warning(0);
else if (version == '12.0(11)ST4')
  security_warning(0);
else if (version == '12.0(12)')
  security_warning(0);
else if (version == '12.0(12a)')
  security_warning(0);
else if (version == '12.0(12)S')
  security_warning(0);
else if (version == '12.0(12)S0830')
  security_warning(0);
else if (version == '12.0(12)S0912')
  security_warning(0);
else if (version == '12.0(12)S0916')
  security_warning(0);
else if (version == '12.0(12)S0918')
  security_warning(0);
else if (version == '12.0(12)S1')
  security_warning(0);
else if (version == '12.0(12)S2')
  security_warning(0);
else if (version == '12.0(12)S3')
  security_warning(0);
else if (version == '12.0(12)S4')
  security_warning(0);
else if (version == '12.0(12)SC')
  security_warning(0);
else if (version == '12.0(13)')
  security_warning(0);
else if (version == '12.0(13a)')
  security_warning(0);
else if (version == '12.0(13)S')
  security_warning(0);
else if (version == '12.0(13)S1')
  security_warning(0);
else if (version == '12.0(13)S1016')
  security_warning(0);
else if (version == '12.0(13)S1022')
  security_warning(0);
else if (version == '12.0(13)S1023')
  security_warning(0);
else if (version == '12.0(13)S2')
  security_warning(0);
else if (version == '12.0(13)S2a')
  security_warning(0);
else if (version == '12.0(13)S3')
  security_warning(0);
else if (version == '12.0(13)S4')
  security_warning(0);
else if (version == '12.0(13)S5')
  security_warning(0);
else if (version == '12.0(13)S5a')
  security_warning(0);
else if (version == '12.0(13)S5b')
  security_warning(0);
else if (version == '12.0(13)S6')
  security_warning(0);
else if (version == '12.0(13)S7')
  security_warning(0);
else if (version == '12.0(13)S8')
  security_warning(0);
else if (version == '12.0(13)SC')
  security_warning(0);
else if (version == '12.0(14)')
  security_warning(0);
else if (version == '12.0(14a)')
  security_warning(0);
else if (version == '12.0(14)S')
  security_warning(0);
else if (version == '12.0(14)S1')
  security_warning(0);
else if (version == '12.0(14)S1205')
  security_warning(0);
else if (version == '12.0(14)S1211')
  security_warning(0);
else if (version == '12.0(14)S1213')
  security_warning(0);
else if (version == '12.0(14)S1226')
  security_warning(0);
else if (version == '12.0(14)S2')
  security_warning(0);
else if (version == '12.0(14)S3')
  security_warning(0);
else if (version == '12.0(14)S4')
  security_warning(0);
else if (version == '12.0(14)S5')
  security_warning(0);
else if (version == '12.0(14)S6')
  security_warning(0);
else if (version == '12.0(14)S7')
  security_warning(0);
else if (version == '12.0(14)S8')
  security_warning(0);
else if (version == '12.0(14)SC')
  security_warning(0);
else if (version == '12.0(14)SL')
  security_warning(0);
else if (version == '12.0(14)SL1')
  security_warning(0);
else if (version == '12.0(14)ST')
  security_warning(0);
else if (version == '12.0(14)ST1')
  security_warning(0);
else if (version == '12.0(14)ST2')
  security_warning(0);
else if (version == '12.0(14)ST3')
  security_warning(0);
else if (version == '12.0(15)')
  security_warning(0);
else if (version == '12.0(15a)')
  security_warning(0);
else if (version == '12.0(15b)')
  security_warning(0);
else if (version == '12.0(15)S')
  security_warning(0);
else if (version == '12.0(15)S0205')
  security_warning(0);
else if (version == '12.0(15)S0209')
  security_warning(0);
else if (version == '12.0(15)S0212')
  security_warning(0);
else if (version == '12.0(15)S0215')
  security_warning(0);
else if (version == '12.0(15)S0216')
  security_warning(0);
else if (version == '12.0(15)S1')
  security_warning(0);
else if (version == '12.0(15)S2')
  security_warning(0);
else if (version == '12.0(15)S3')
  security_warning(0);
else if (version == '12.0(15)S3a')
  security_warning(0);
else if (version == '12.0(15)S4')
  security_warning(0);
else if (version == '12.0(15)S5')
  security_warning(0);
else if (version == '12.0(15)S6')
  security_warning(0);
else if (version == '12.0(15)S7')
  security_warning(0);
else if (version == '12.0(15)SC')
  security_warning(0);
else if (version == '12.0(15)SC1')
  security_warning(0);
else if (version == '12.0(15)SL')
  security_warning(0);
else if (version == '12.0(16)')
  security_warning(0);
else if (version == '12.0(16a)')
  security_warning(0);
else if (version == '12.0(16b)')
  security_warning(0);
else if (version == '12.0(16)S')
  security_warning(0);
else if (version == '12.0(16)S0416')
  security_warning(0);
else if (version == '12.0(16)S0422')
  security_warning(0);
else if (version == '12.0(16)S0425')
  security_warning(0);
else if (version == '12.0(16)S1')
  security_warning(0);
else if (version == '12.0(16)S10')
  security_warning(0);
else if (version == '12.0(16)S11')
  security_warning(0);
else if (version == '12.0(16)S12')
  security_warning(0);
else if (version == '12.0(16)S1a')
  security_warning(0);
else if (version == '12.0(16)S2')
  security_warning(0);
else if (version == '12.0(16)S3')
  security_warning(0);
else if (version == '12.0(16)S4')
  security_warning(0);
else if (version == '12.0(16)S4a')
  security_warning(0);
else if (version == '12.0(16)S5')
  security_warning(0);
else if (version == '12.0(16)S6')
  security_warning(0);
else if (version == '12.0(16)S7')
  security_warning(0);
else if (version == '12.0(16)S8')
  security_warning(0);
else if (version == '12.0(16)S8a')
  security_warning(0);
else if (version == '12.0(16)S9')
  security_warning(0);
else if (version == '12.0(16)SC')
  security_warning(0);
else if (version == '12.0(16)SC1')
  security_warning(0);
else if (version == '12.0(16)SC2')
  security_warning(0);
else if (version == '12.0(16)SC3')
  security_warning(0);
else if (version == '12.0(16)ST')
  security_warning(0);
else if (version == '12.0(16)ST1')
  security_warning(0);
else if (version == '12.0(17)')
  security_warning(0);
else if (version == '12.0(17a)')
  security_warning(0);
else if (version == '12.0(17)S')
  security_warning(0);
else if (version == '12.0(17)S0620')
  security_warning(0);
else if (version == '12.0(17)S0621')
  security_warning(0);
else if (version == '12.0(17)S1')
  security_warning(0);
else if (version == '12.0(17)S2')
  security_warning(0);
else if (version == '12.0(17)S3')
  security_warning(0);
else if (version == '12.0(17)S4')
  security_warning(0);
else if (version == '12.0(17)S5')
  security_warning(0);
else if (version == '12.0(17)S6')
  security_warning(0);
else if (version == '12.0(17)S7')
  security_warning(0);
else if (version == '12.0(17)SL')
  security_warning(0);
else if (version == '12.0(17)SL1')
  security_warning(0);
else if (version == '12.0(17)SL2')
  security_warning(0);
else if (version == '12.0(17)SL3')
  security_warning(0);
else if (version == '12.0(17)SL4')
  security_warning(0);
else if (version == '12.0(17)SL5')
  security_warning(0);
else if (version == '12.0(17)SL6')
  security_warning(0);
else if (version == '12.0(17)SL7')
  security_warning(0);
else if (version == '12.0(17)SL8')
  security_warning(0);
else if (version == '12.0(17)SL9')
  security_warning(0);
else if (version == '12.0(17)ST')
  security_warning(0);
else if (version == '12.0(17)ST0622')
  security_warning(0);
else if (version == '12.0(17)ST071201')
  security_warning(0);
else if (version == '12.0(17)ST0717')
  security_warning(0);
else if (version == '12.0(17)ST0719')
  security_warning(0);
else if (version == '12.0(17)ST0726')
  security_warning(0);
else if (version == '12.0(17)ST1')
  security_warning(0);
else if (version == '12.0(17)ST10')
  security_warning(0);
else if (version == '12.0(17)ST2')
  security_warning(0);
else if (version == '12.0(17)ST3')
  security_warning(0);
else if (version == '12.0(17)ST4')
  security_warning(0);
else if (version == '12.0(17)ST5')
  security_warning(0);
else if (version == '12.0(17)ST6')
  security_warning(0);
else if (version == '12.0(17)ST7')
  security_warning(0);
else if (version == '12.0(17)ST8')
  security_warning(0);
else if (version == '12.0(17)ST9')
  security_warning(0);
else if (version == '12.0(18)')
  security_warning(0);
else if (version == '12.0(18a)')
  security_warning(0);
else if (version == '12.0(18b)')
  security_warning(0);
else if (version == '12.0(18)S')
  security_warning(0);
else if (version == '12.0(18)S0814')
  security_warning(0);
else if (version == '12.0(18)S0906')
  security_warning(0);
else if (version == '12.0(18)S1')
  security_warning(0);
else if (version == '12.0(18)S2')
  security_warning(0);
else if (version == '12.0(18)S3')
  security_warning(0);
else if (version == '12.0(18)S4')
  security_warning(0);
else if (version == '12.0(18)S5')
  security_warning(0);
else if (version == '12.0(18)S5a')
  security_warning(0);
else if (version == '12.0(18)S6')
  security_warning(0);
else if (version == '12.0(18)S7')
  security_warning(0);
else if (version == '12.0(18)ST')
  security_warning(0);
else if (version == '12.0(18)ST1')
  security_warning(0);
else if (version == '12.0(19)')
  security_warning(0);
else if (version == '12.0(19a)')
  security_warning(0);
else if (version == '12.0(19b)')
  security_warning(0);
else if (version == '12.0(19)S')
  security_warning(0);
else if (version == '12.0(19)S1')
  security_warning(0);
else if (version == '12.0(19)S1128')
  security_warning(0);
else if (version == '12.0(19)S2')
  security_warning(0);
else if (version == '12.0(19)S2a')
  security_warning(0);
else if (version == '12.0(19)S3')
  security_warning(0);
else if (version == '12.0(19)S4')
  security_warning(0);
else if (version == '12.0(19)SL')
  security_warning(0);
else if (version == '12.0(19)SL1')
  security_warning(0);
else if (version == '12.0(19)SL2')
  security_warning(0);
else if (version == '12.0(19)SL3')
  security_warning(0);
else if (version == '12.0(19)SL4')
  security_warning(0);
else if (version == '12.0(19)SP')
  security_warning(0);
else if (version == '12.0(19)ST')
  security_warning(0);
else if (version == '12.0(19)ST1')
  security_warning(0);
else if (version == '12.0(19)ST1114')
  security_warning(0);
else if (version == '12.0(19)ST1116')
  security_warning(0);
else if (version == '12.0(19)ST2')
  security_warning(0);
else if (version == '12.0(19)ST3')
  security_warning(0);
else if (version == '12.0(19)ST4')
  security_warning(0);
else if (version == '12.0(19)ST5')
  security_warning(0);
else if (version == '12.0(19)ST6')
  security_warning(0);
else if (version == '12.0(1)T')
  security_warning(0);
else if (version == '12.0(1)T1')
  security_warning(0);
else if (version == '12.0(1)XB')
  security_warning(0);
else if (version == '12.0(1)XB1')
  security_warning(0);
else if (version == '12.0(1)XE')
  security_warning(0);
else if (version == '12.0(20)')
  security_warning(0);
else if (version == '12.0(202)TEST')
  security_warning(0);
else if (version == '12.0(20a)')
  security_warning(0);
else if (version == '12.0(20)SP')
  security_warning(0);
else if (version == '12.0(20)SP1')
  security_warning(0);
else if (version == '12.0(20)SP2')
  security_warning(0);
else if (version == '12.0(20)ST')
  security_warning(0);
else if (version == '12.0(20)ST1')
  security_warning(0);
else if (version == '12.0(20)ST2')
  security_warning(0);
else if (version == '12.0(20)ST3')
  security_warning(0);
else if (version == '12.0(20)ST4')
  security_warning(0);
else if (version == '12.0(20)ST5')
  security_warning(0);
else if (version == '12.0(20)ST6')
  security_warning(0);
else if (version == '12.0(21)')
  security_warning(0);
else if (version == '12.0(21a)')
  security_warning(0);
else if (version == '12.0(21)S')
  security_warning(0);
else if (version == '12.0(21)S0122')
  security_warning(0);
else if (version == '12.0(21)S0130')
  security_warning(0);
else if (version == '12.0(21)S0207')
  security_warning(0);
else if (version == '12.0(21)S0213')
  security_warning(0);
else if (version == '12.0(21)S1')
  security_warning(0);
else if (version == '12.0(21)S2')
  security_warning(0);
else if (version == '12.0(21)S3')
  security_warning(0);
else if (version == '12.0(21)S4')
  security_warning(0);
else if (version == '12.0(21)S4a')
  security_warning(0);
else if (version == '12.0(21)S5')
  security_warning(0);
else if (version == '12.0(21)S5a')
  security_warning(0);
else if (version == '12.0(21)S6')
  security_warning(0);
else if (version == '12.0(21)S6a')
  security_warning(0);
else if (version == '12.0(21)S7')
  security_warning(0);
else if (version == '12.0(21)S8')
  security_warning(0);
else if (version == '12.0(21)SP')
  security_warning(0);
else if (version == '12.0(21)SP0722')
  security_warning(0);
else if (version == '12.0(21)SP0726')
  security_warning(0);
else if (version == '12.0(21)SP1')
  security_warning(0);
else if (version == '12.0(21)SP2')
  security_warning(0);
else if (version == '12.0(21)SP3')
  security_warning(0);
else if (version == '12.0(21)SP4')
  security_warning(0);
else if (version == '12.0(21)ST')
  security_warning(0);
else if (version == '12.0(21)ST0318')
  security_warning(0);
else if (version == '12.0(21)ST0321')
  security_warning(0);
else if (version == '12.0(21)ST0326')
  security_warning(0);
else if (version == '12.0(21)ST1')
  security_warning(0);
else if (version == '12.0(21)ST2')
  security_warning(0);
else if (version == '12.0(21)ST2a')
  security_warning(0);
else if (version == '12.0(21)ST2b')
  security_warning(0);
else if (version == '12.0(21)ST3')
  security_warning(0);
else if (version == '12.0(21)ST3a')
  security_warning(0);
else if (version == '12.0(21)ST4')
  security_warning(0);
else if (version == '12.0(21)ST5')
  security_warning(0);
else if (version == '12.0(21)ST6')
  security_warning(0);
else if (version == '12.0(21)ST6a')
  security_warning(0);
else if (version == '12.0(21)ST7')
  security_warning(0);
else if (version == '12.0(21)SX')
  security_warning(0);
else if (version == '12.0(21)SX1')
  security_warning(0);
else if (version == '12.0(21)SZ')
  security_warning(0);
else if (version == '12.0(2a)T1')
  security_warning(0);
else if (version == '12.0(2)DB')
  security_warning(0);
else if (version == '12.0(2)T')
  security_warning(0);
else if (version == '12.0(2)T1')
  security_warning(0);
else if (version == '12.0(2)XC')
  security_warning(0);
else if (version == '12.0(2)XC1')
  security_warning(0);
else if (version == '12.0(2)XC2')
  security_warning(0);
else if (version == '12.0(2)XD')
  security_warning(0);
else if (version == '12.0(2)XD1')
  security_warning(0);
else if (version == '12.0(2)XE')
  security_warning(0);
else if (version == '12.0(2)XE1')
  security_warning(0);
else if (version == '12.0(2)XE2')
  security_warning(0);
else if (version == '12.0(2)XE3')
  security_warning(0);
else if (version == '12.0(2)XE4')
  security_warning(0);
else if (version == '12.0(2)XF')
  security_warning(0);
else if (version == '12.0(2)XF1')
  security_warning(0);
else if (version == '12.0(2)XF2')
  security_warning(0);
else if (version == '12.0(3b)VIR')
  security_warning(0);
else if (version == '12.0(3)DB')
  security_warning(0);
else if (version == '12.0(3)DC')
  security_warning(0);
else if (version == '12.0(3)DC1')
  security_warning(0);
else if (version == '12.0(3r)T1')
  security_warning(0);
else if (version == '12.0(3)S')
  security_warning(0);
else if (version == '12.0(3)T')
  security_warning(0);
else if (version == '12.0(3)T1')
  security_warning(0);
else if (version == '12.0(3)T2')
  security_warning(0);
else if (version == '12.0(3)T3')
  security_warning(0);
else if (version == '12.0(3)XG')
  security_warning(0);
else if (version == '12.0(4)DB')
  security_warning(0);
else if (version == '12.0(4)S')
  security_warning(0);
else if (version == '12.0(4)T')
  security_warning(0);
else if (version == '12.0(4)T1')
  security_warning(0);
else if (version == '12.0(4)XE')
  security_warning(0);
else if (version == '12.0(4)XE1')
  security_warning(0);
else if (version == '12.0(4)XE2')
  security_warning(0);
else if (version == '12.0(4)XH')
  security_warning(0);
else if (version == '12.0(4)XH1')
  security_warning(0);
else if (version == '12.0(4)XH2')
  security_warning(0);
else if (version == '12.0(4)XH3')
  security_warning(0);
else if (version == '12.0(4)XH4')
  security_warning(0);
else if (version == '12.0(4)XJ')
  security_warning(0);
else if (version == '12.0(4)XJ1')
  security_warning(0);
else if (version == '12.0(4)XJ2')
  security_warning(0);
else if (version == '12.0(4)XJ3')
  security_warning(0);
else if (version == '12.0(4)XJ4')
  security_warning(0);
else if (version == '12.0(4)XJ5')
  security_warning(0);
else if (version == '12.0(4)XJ6')
  security_warning(0);
else if (version == '12.0(4)XL')
  security_warning(0);
else if (version == '12.0(4)XL1')
  security_warning(0);
else if (version == '12.0(4)XM')
  security_warning(0);
else if (version == '12.0(4)XM1')
  security_warning(0);
else if (version == '12.0(5)DA')
  security_warning(0);
else if (version == '12.0(5)DA1')
  security_warning(0);
else if (version == '12.0(5)DB')
  security_warning(0);
else if (version == '12.0(5)DC')
  security_warning(0);
else if (version == '12.0(5r)T')
  security_warning(0);
else if (version == '12.0(5r)T1')
  security_warning(0);
else if (version == '12.0(5r)XE')
  security_warning(0);
else if (version == '12.0(5r)XE1')
  security_warning(0);
else if (version == '12.0(5r)XE2')
  security_warning(0);
else if (version == '12.0(5r)XS')
  security_warning(0);
else if (version == '12.0(5)S')
  security_warning(0);
else if (version == '12.0(5)S0714')
  security_warning(0);
else if (version == '12.0(5)S0722')
  security_warning(0);
else if (version == '12.0(5)S0723')
  security_warning(0);
else if (version == '12.0(5)S0726')
  security_warning(0);
else if (version == '12.0(5)S0727')
  security_warning(0);
else if (version == '12.0(5)T')
  security_warning(0);
else if (version == '12.0(5)T1')
  security_warning(0);
else if (version == '12.0(5)T2')
  security_warning(0);
else if (version == '12.0(5)WC10')
  security_warning(0);
else if (version == '12.0(5)WC11')
  security_warning(0);
else if (version == '12.0(5)WC12')
  security_warning(0);
else if (version == '12.0(5)WC13')
  security_warning(0);
else if (version == '12.0(5)WC14')
  security_warning(0);
else if (version == '12.0(5)WC15')
  security_warning(0);
else if (version == '12.0(5)WC16')
  security_warning(0);
else if (version == '12.0(5)WC2')
  security_warning(0);
else if (version == '12.0(5)WC2b')
  security_warning(0);
else if (version == '12.0(5)WC3')
  security_warning(0);
else if (version == '12.0(5)WC3a')
  security_warning(0);
else if (version == '12.0(5)WC3b')
  security_warning(0);
else if (version == '12.0(5)WC4')
  security_warning(0);
else if (version == '12.0(5)WC4a')
  security_warning(0);
else if (version == '12.0(5)WC5')
  security_warning(0);
else if (version == '12.0(5)WC5a')
  security_warning(0);
else if (version == '12.0(5)WC6')
  security_warning(0);
else if (version == '12.0(5)WC7')
  security_warning(0);
else if (version == '12.0(5)WC8')
  security_warning(0);
else if (version == '12.0(5)WC9')
  security_warning(0);
else if (version == '12.0(5)WC9a')
  security_warning(0);
else if (version == '12.0(5)XE')
  security_warning(0);
else if (version == '12.0(5)XE1')
  security_warning(0);
else if (version == '12.0(5)XE2')
  security_warning(0);
else if (version == '12.0(5)XE3')
  security_warning(0);
else if (version == '12.0(5)XE4')
  security_warning(0);
else if (version == '12.0(5)XE5')
  security_warning(0);
else if (version == '12.0(5)XE6')
  security_warning(0);
else if (version == '12.0(5)XE7')
  security_warning(0);
else if (version == '12.0(5)XE8')
  security_warning(0);
else if (version == '12.0(5)XK')
  security_warning(0);
else if (version == '12.0(5)XK1')
  security_warning(0);
else if (version == '12.0(5)XK2')
  security_warning(0);
else if (version == '12.0(5)XN')
  security_warning(0);
else if (version == '12.0(5)XQ')
  security_warning(0);
else if (version == '12.0(5)XQ1')
  security_warning(0);
else if (version == '12.0(5)XS')
  security_warning(0);
else if (version == '12.0(5)XS1')
  security_warning(0);
else if (version == '12.0(5)XS2')
  security_warning(0);
else if (version == '12.0(5)XT1')
  security_warning(0);
else if (version == '12.0(6r)T')
  security_warning(0);
else if (version == '12.0(6r)T1')
  security_warning(0);
else if (version == '12.0(6r)T2')
  security_warning(0);
else if (version == '12.0(6r)T3')
  security_warning(0);
else if (version == '12.0(6r)T4')
  security_warning(0);
else if (version == '12.0(6)S')
  security_warning(0);
else if (version == '12.0(6)S1')
  security_warning(0);
else if (version == '12.0(6)S2')
  security_warning(0);
else if (version == '12.0(6)SC')
  security_warning(0);
else if (version == '12.0(7)DB')
  security_warning(0);
else if (version == '12.0(7)DB1')
  security_warning(0);
else if (version == '12.0(7)DB2')
  security_warning(0);
else if (version == '12.0(7r)XK')
  security_warning(0);
else if (version == '12.0(7)S')
  security_warning(0);
else if (version == '12.0(7)S1')
  security_warning(0);
else if (version == '12.0(7)S1110')
  security_warning(0);
else if (version == '12.0(7)S1113')
  security_warning(0);
else if (version == '12.0(7)S1116')
  security_warning(0);
else if (version == '12.0(7)S1123')
  security_warning(0);
else if (version == '12.0(7)SC')
  security_warning(0);
else if (version == '12.0(7)T')
  security_warning(0);
else if (version == '12.0(7)T1')
  security_warning(0);
else if (version == '12.0(7)T2')
  security_warning(0);
else if (version == '12.0(7)T3')
  security_warning(0);
else if (version == '12.0(7)XE')
  security_warning(0);
else if (version == '12.0(7)XE1')
  security_warning(0);
else if (version == '12.0(7)XE2')
  security_warning(0);
else if (version == '12.0(7)XF1')
  security_warning(0);
else if (version == '12.0(7)XK')
  security_warning(0);
else if (version == '12.0(7)XK1')
  security_warning(0);
else if (version == '12.0(7)XK2')
  security_warning(0);
else if (version == '12.0(7)XK3')
  security_warning(0);
else if (version == '12.0(7)XR')
  security_warning(0);
else if (version == '12.0(7)XR1')
  security_warning(0);
else if (version == '12.0(7)XR2')
  security_warning(0);
else if (version == '12.0(7)XR3')
  security_warning(0);
else if (version == '12.0(7)XR4')
  security_warning(0);
else if (version == '12.0(7)XV')
  security_warning(0);
else if (version == '12.0(8)DA')
  security_warning(0);
else if (version == '12.0(8)DA1')
  security_warning(0);
else if (version == '12.0(8)DA2')
  security_warning(0);
else if (version == '12.0(8)DA3')
  security_warning(0);
else if (version == '12.0(8)DA4')
  security_warning(0);
else if (version == '12.0(8)S')
  security_warning(0);
else if (version == '12.0(8)S0208')
  security_warning(0);
else if (version == '12.0(8)S0412')
  security_warning(0);
else if (version == '12.0(8)S1')
  security_warning(0);
else if (version == '12.0(8)SC')
  security_warning(0);
else if (version == '12.0(8)SC1')
  security_warning(0);
else if (version == '12.0(9r)SL')
  security_warning(0);
else if (version == '12.0(9r)SL1')
  security_warning(0);
else if (version == '12.0(9r)SL2')
  security_warning(0);
else if (version == '12.0(9)S')
  security_warning(0);
else if (version == '12.0(9)S0310')
  security_warning(0);
else if (version == '12.0(9)S1')
  security_warning(0);
else if (version == '12.0(9)S2')
  security_warning(0);
else if (version == '12.0(9)S3')
  security_warning(0);
else if (version == '12.0(9)S4')
  security_warning(0);
else if (version == '12.0(9)S5')
  security_warning(0);
else if (version == '12.0(9)S6')
  security_warning(0);
else if (version == '12.0(9)S7')
  security_warning(0);
else if (version == '12.0(9)S8')
  security_warning(0);
else if (version == '12.0(9)SC')
  security_warning(0);
else if (version == '12.0(9)SL')
  security_warning(0);
else if (version == '12.0(9)SL1')
  security_warning(0);
else if (version == '12.0(9)SL2')
  security_warning(0);
else if (version == '12.0(9)ST')
  security_warning(0);
else if (version == '12.1(0)PCHK1')
  security_warning(0);
else if (version == '12.1(0)PCHK10')
  security_warning(0);
else if (version == '12.1(0)PCHK11')
  security_warning(0);
else if (version == '12.1(0)PCHK12')
  security_warning(0);
else if (version == '12.1(0)PCHK13')
  security_warning(0);
else if (version == '12.1(0)PCHK14')
  security_warning(0);
else if (version == '12.1(0)PCHK15')
  security_warning(0);
else if (version == '12.1(0)PCHK16')
  security_warning(0);
else if (version == '12.1(0)PCHK17')
  security_warning(0);
else if (version == '12.1(0)PCHK18')
  security_warning(0);
else if (version == '12.1(0)PCHK19')
  security_warning(0);
else if (version == '12.1(0)PCHK2')
  security_warning(0);
else if (version == '12.1(0)PCHK20')
  security_warning(0);
else if (version == '12.1(0)PCHK21')
  security_warning(0);
else if (version == '12.1(0)PCHK22')
  security_warning(0);
else if (version == '12.1(0)PCHK23')
  security_warning(0);
else if (version == '12.1(0)PCHK24')
  security_warning(0);
else if (version == '12.1(0)PCHK3')
  security_warning(0);
else if (version == '12.1(0)PCHK4')
  security_warning(0);
else if (version == '12.1(0)PCHK5')
  security_warning(0);
else if (version == '12.1(0)PCHK6')
  security_warning(0);
else if (version == '12.1(0)PCHK7')
  security_warning(0);
else if (version == '12.1(0)PCHK8')
  security_warning(0);
else if (version == '12.1(0)PCHK9')
  security_warning(0);
else if (version == '12.1(0)PCHK92')
  security_warning(0);
else if (version == '12.1(1)')
  security_warning(0);
else if (version == '12.1(10)')
  security_warning(0);
else if (version == '12.1(10a)')
  security_warning(0);
else if (version == '12.1(10)AA')
  security_warning(0);
else if (version == '12.1(10)E')
  security_warning(0);
else if (version == '12.1(10)E1')
  security_warning(0);
else if (version == '12.1(10)E2')
  security_warning(0);
else if (version == '12.1(10)E3')
  security_warning(0);
else if (version == '12.1(10)E4')
  security_warning(0);
else if (version == '12.1(10)E5')
  security_warning(0);
else if (version == '12.1(10)E6')
  security_warning(0);
else if (version == '12.1(10)E6a')
  security_warning(0);
else if (version == '12.1(10)E7')
  security_warning(0);
else if (version == '12.1(10)E8')
  security_warning(0);
else if (version == '12.1(10)EC')
  security_warning(0);
else if (version == '12.1(10)EC1')
  security_warning(0);
else if (version == '12.1(10)EX')
  security_warning(0);
else if (version == '12.1(10)EX1')
  security_warning(0);
else if (version == '12.1(10)EX2')
  security_warning(0);
else if (version == '12.1(1a)')
  security_warning(0);
else if (version == '12.1(1)AA')
  security_warning(0);
else if (version == '12.1(1)AA1')
  security_warning(0);
else if (version == '12.1(1a)T1')
  security_warning(0);
else if (version == '12.1(1b)')
  security_warning(0);
else if (version == '12.1(1c)')
  security_warning(0);
else if (version == '12.1(1)DA')
  security_warning(0);
else if (version == '12.1(1)DA1')
  security_warning(0);
else if (version == '12.1(1)DB')
  security_warning(0);
else if (version == '12.1(1)DB1')
  security_warning(0);
else if (version == '12.1(1)DB2')
  security_warning(0);
else if (version == '12.1(1)DC')
  security_warning(0);
else if (version == '12.1(1)DC1')
  security_warning(0);
else if (version == '12.1(1)DC2')
  security_warning(0);
else if (version == '12.1(1)E')
  security_warning(0);
else if (version == '12.1(1)E1')
  security_warning(0);
else if (version == '12.1(1)E2')
  security_warning(0);
else if (version == '12.1(1)E3')
  security_warning(0);
else if (version == '12.1(1)E4')
  security_warning(0);
else if (version == '12.1(1)E5')
  security_warning(0);
else if (version == '12.1(1)E6')
  security_warning(0);
else if (version == '12.1(1)EX')
  security_warning(0);
else if (version == '12.1(1)EX1')
  security_warning(0);
else if (version == '12.1(1)GA')
  security_warning(0);
else if (version == '12.1(1)GA1')
  security_warning(0);
else if (version == '12.1(1)PE')
  security_warning(0);
else if (version == '12.1(1r)EX')
  security_warning(0);
else if (version == '12.1(1r)XC')
  security_warning(0);
else if (version == '12.1(1r)XD')
  security_warning(0);
else if (version == '12.1(1)T')
  security_warning(0);
else if (version == '12.1(1)XA')
  security_warning(0);
else if (version == '12.1(1)XA1')
  security_warning(0);
else if (version == '12.1(1)XA2')
  security_warning(0);
else if (version == '12.1(1)XA3')
  security_warning(0);
else if (version == '12.1(1)XA4')
  security_warning(0);
else if (version == '12.1(1)XC')
  security_warning(0);
else if (version == '12.1(1)XC1')
  security_warning(0);
else if (version == '12.1(1)XD')
  security_warning(0);
else if (version == '12.1(1)XD1')
  security_warning(0);
else if (version == '12.1(1)XD2')
  security_warning(0);
else if (version == '12.1(1)XE')
  security_warning(0);
else if (version == '12.1(1)XE1')
  security_warning(0);
else if (version == '12.1(2)')
  security_warning(0);
else if (version == '12.1(2a)')
  security_warning(0);
else if (version == '12.1(2a)AA')
  security_warning(0);
else if (version == '12.1(2a)T1')
  security_warning(0);
else if (version == '12.1(2a)T2')
  security_warning(0);
else if (version == '12.1(2a)XH')
  security_warning(0);
else if (version == '12.1(2a)XH1')
  security_warning(0);
else if (version == '12.1(2a)XH2')
  security_warning(0);
else if (version == '12.1(2a)XH3')
  security_warning(0);
else if (version == '12.1(2b)')
  security_warning(0);
else if (version == '12.1(2)DA')
  security_warning(0);
else if (version == '12.1(2)E')
  security_warning(0);
else if (version == '12.1(2)E1')
  security_warning(0);
else if (version == '12.1(2)E2')
  security_warning(0);
else if (version == '12.1(2)EC')
  security_warning(0);
else if (version == '12.1(2)EC1')
  security_warning(0);
else if (version == '12.1(2)GB')
  security_warning(0);
else if (version == '12.1(2r)E')
  security_warning(0);
else if (version == '12.1(2r)XD')
  security_warning(0);
else if (version == '12.1(2r)XD1')
  security_warning(0);
else if (version == '12.1(2r)XH')
  security_warning(0);
else if (version == '12.1(2)T')
  security_warning(0);
else if (version == '12.1(2)XF')
  security_warning(0);
else if (version == '12.1(2)XF1')
  security_warning(0);
else if (version == '12.1(2)XF2')
  security_warning(0);
else if (version == '12.1(2)XF3')
  security_warning(0);
else if (version == '12.1(2)XF4')
  security_warning(0);
else if (version == '12.1(2)XF5')
  security_warning(0);
else if (version == '12.1(2)XT2')
  security_warning(0);
else if (version == '12.1(3)')
  security_warning(0);
else if (version == '12.1(3a)')
  security_warning(0);
else if (version == '12.1(3)AA')
  security_warning(0);
else if (version == '12.1(3a)E')
  security_warning(0);
else if (version == '12.1(3a)E1')
  security_warning(0);
else if (version == '12.1(3a)E2')
  security_warning(0);
else if (version == '12.1(3a)E3')
  security_warning(0);
else if (version == '12.1(3a)E4')
  security_warning(0);
else if (version == '12.1(3a)E5')
  security_warning(0);
else if (version == '12.1(3a)E6')
  security_warning(0);
else if (version == '12.1(3a)E7')
  security_warning(0);
else if (version == '12.1(3a)E8')
  security_warning(0);
else if (version == '12.1(3a)EC')
  security_warning(0);
else if (version == '12.1(3a)EC1')
  security_warning(0);
else if (version == '12.1(3a)T1')
  security_warning(0);
else if (version == '12.1(3a)T2')
  security_warning(0);
else if (version == '12.1(3a)T3')
  security_warning(0);
else if (version == '12.1(3a)T4')
  security_warning(0);
else if (version == '12.1(3a)T5')
  security_warning(0);
else if (version == '12.1(3a)T6')
  security_warning(0);
else if (version == '12.1(3a)T7')
  security_warning(0);
else if (version == '12.1(3a)T8')
  security_warning(0);
else if (version == '12.1(3a)XI1')
  security_warning(0);
else if (version == '12.1(3a)XI2')
  security_warning(0);
else if (version == '12.1(3a)XI3')
  security_warning(0);
else if (version == '12.1(3a)XI4')
  security_warning(0);
else if (version == '12.1(3a)XI5')
  security_warning(0);
else if (version == '12.1(3a)XI6')
  security_warning(0);
else if (version == '12.1(3a)XI7')
  security_warning(0);
else if (version == '12.1(3a)XI8')
  security_warning(0);
else if (version == '12.1(3a)XI9')
  security_warning(0);
else if (version == '12.1(3a)XL1')
  security_warning(0);
else if (version == '12.1(3a)XL2')
  security_warning(0);
else if (version == '12.1(3a)XL3')
  security_warning(0);
else if (version == '12.1(3b)')
  security_warning(0);
else if (version == '12.1(3)DA')
  security_warning(0);
else if (version == '12.1(3)DB')
  security_warning(0);
else if (version == '12.1(3)DB1')
  security_warning(0);
else if (version == '12.1(3)DC')
  security_warning(0);
else if (version == '12.1(3)DC1')
  security_warning(0);
else if (version == '12.1(3)DC2')
  security_warning(0);
else if (version == '12.1(3r)E')
  security_warning(0);
else if (version == '12.1(3r)E1')
  security_warning(0);
else if (version == '12.1(3r)E2')
  security_warning(0);
else if (version == '12.1(3r)T')
  security_warning(0);
else if (version == '12.1(3r)T1')
  security_warning(0);
else if (version == '12.1(3r)T2')
  security_warning(0);
else if (version == '12.1(3r)XI1')
  security_warning(0);
else if (version == '12.1(3r)XK')
  security_warning(0);
else if (version == '12.1(3r)XL')
  security_warning(0);
else if (version == '12.1(3r)XP')
  security_warning(0);
else if (version == '12.1(3)T')
  security_warning(0);
else if (version == '12.1(3)XG')
  security_warning(0);
else if (version == '12.1(3)XG1')
  security_warning(0);
else if (version == '12.1(3)XG2')
  security_warning(0);
else if (version == '12.1(3)XG3')
  security_warning(0);
else if (version == '12.1(3)XG4')
  security_warning(0);
else if (version == '12.1(3)XG5')
  security_warning(0);
else if (version == '12.1(3)XG6')
  security_warning(0);
else if (version == '12.1(3)XI')
  security_warning(0);
else if (version == '12.1(3)XJ')
  security_warning(0);
else if (version == '12.1(3)XL')
  security_warning(0);
else if (version == '12.1(3)XP')
  security_warning(0);
else if (version == '12.1(3)XP1')
  security_warning(0);
else if (version == '12.1(3)XP2')
  security_warning(0);
else if (version == '12.1(3)XP3')
  security_warning(0);
else if (version == '12.1(3)XP4')
  security_warning(0);
else if (version == '12.1(3)XQ')
  security_warning(0);
else if (version == '12.1(3)XQ1')
  security_warning(0);
else if (version == '12.1(3)XQ2')
  security_warning(0);
else if (version == '12.1(3)XQ3')
  security_warning(0);
else if (version == '12.1(3)XS')
  security_warning(0);
else if (version == '12.1(3)XW')
  security_warning(0);
else if (version == '12.1(3)XW1')
  security_warning(0);
else if (version == '12.1(3)XW2')
  security_warning(0);
else if (version == '12.1(4)')
  security_warning(0);
else if (version == '12.1(4a)')
  security_warning(0);
else if (version == '12.1(4)AA')
  security_warning(0);
else if (version == '12.1(4b)')
  security_warning(0);
else if (version == '12.1(4c)')
  security_warning(0);
else if (version == '12.1(4)CX')
  security_warning(0);
else if (version == '12.1(4)DA')
  security_warning(0);
else if (version == '12.1(4)DB')
  security_warning(0);
else if (version == '12.1(4)DB1')
  security_warning(0);
else if (version == '12.1(4)DB2')
  security_warning(0);
else if (version == '12.1(4)E')
  security_warning(0);
else if (version == '12.1(4)E1')
  security_warning(0);
else if (version == '12.1(4)E2')
  security_warning(0);
else if (version == '12.1(4)E3')
  security_warning(0);
else if (version == '12.1(4)EC')
  security_warning(0);
else if (version == '12.1(4r)E')
  security_warning(0);
else if (version == '12.1(4)XY')
  security_warning(0);
else if (version == '12.1(4)XY1')
  security_warning(0);
else if (version == '12.1(4)XY2')
  security_warning(0);
else if (version == '12.1(4)XY3')
  security_warning(0);
else if (version == '12.1(4)XY4')
  security_warning(0);
else if (version == '12.1(4)XY5')
  security_warning(0);
else if (version == '12.1(4)XY6')
  security_warning(0);
else if (version == '12.1(4)XY7')
  security_warning(0);
else if (version == '12.1(4)XY8')
  security_warning(0);
else if (version == '12.1(4)XZ')
  security_warning(0);
else if (version == '12.1(4)XZ1')
  security_warning(0);
else if (version == '12.1(4)XZ2')
  security_warning(0);
else if (version == '12.1(4)XZ3')
  security_warning(0);
else if (version == '12.1(4)XZ4')
  security_warning(0);
else if (version == '12.1(4)XZ5')
  security_warning(0);
else if (version == '12.1(4)XZ6')
  security_warning(0);
else if (version == '12.1(4)XZ7')
  security_warning(0);
else if (version == '12.1(5)')
  security_warning(0);
else if (version == '12.1(5a)')
  security_warning(0);
else if (version == '12.1(5)AA')
  security_warning(0);
else if (version == '12.1(5a)E')
  security_warning(0);
else if (version == '12.1(5a)E1')
  security_warning(0);
else if (version == '12.1(5a)E2')
  security_warning(0);
else if (version == '12.1(5a)E3')
  security_warning(0);
else if (version == '12.1(5a)E4')
  security_warning(0);
else if (version == '12.1(5a)E5')
  security_warning(0);
else if (version == '12.1(5a)E6')
  security_warning(0);
else if (version == '12.1(5b)')
  security_warning(0);
else if (version == '12.1(5b)E7')
  security_warning(0);
else if (version == '12.1(5c)')
  security_warning(0);
else if (version == '12.1(5c)E10')
  security_warning(0);
else if (version == '12.1(5c)E11')
  security_warning(0);
else if (version == '12.1(5c)E12')
  security_warning(0);
else if (version == '12.1(5c)E8')
  security_warning(0);
else if (version == '12.1(5c)E9')
  security_warning(0);
else if (version == '12.1(5c)EX')
  security_warning(0);
else if (version == '12.1(5c)EX1')
  security_warning(0);
else if (version == '12.1(5c)EX2')
  security_warning(0);
else if (version == '12.1(5c)EX3')
  security_warning(0);
else if (version == '12.1(5d)')
  security_warning(0);
else if (version == '12.1(5)DA')
  security_warning(0);
else if (version == '12.1(5)DA1')
  security_warning(0);
else if (version == '12.1(5)DB')
  security_warning(0);
else if (version == '12.1(5)DB1')
  security_warning(0);
else if (version == '12.1(5)DB2')
  security_warning(0);
else if (version == '12.1(5)DC')
  security_warning(0);
else if (version == '12.1(5)DC1')
  security_warning(0);
else if (version == '12.1(5)DC2')
  security_warning(0);
else if (version == '12.1(5)DC3')
  security_warning(0);
else if (version == '12.1(5e)')
  security_warning(0);
else if (version == '12.1(5)E')
  security_warning(0);
else if (version == '12.1(5)EC')
  security_warning(0);
else if (version == '12.1(5)EC1')
  security_warning(0);
else if (version == '12.1(5)EX')
  security_warning(0);
else if (version == '12.1(5)EY')
  security_warning(0);
else if (version == '12.1(5)EY1')
  security_warning(0);
else if (version == '12.1(5)EY2')
  security_warning(0);
else if (version == '12.1(5r)E')
  security_warning(0);
else if (version == '12.1(5r)E1')
  security_warning(0);
else if (version == '12.1(5r)T1')
  security_warning(0);
else if (version == '12.1(5r)T2')
  security_warning(0);
else if (version == '12.1(5r)XR')
  security_warning(0);
else if (version == '12.1(5r)XR1')
  security_warning(0);
else if (version == '12.1(5r)XV')
  security_warning(0);
else if (version == '12.1(5r)YA')
  security_warning(0);
else if (version == '12.1(5)T')
  security_warning(0);
else if (version == '12.1(5)T1')
  security_warning(0);
else if (version == '12.1(5)T10')
  security_warning(0);
else if (version == '12.1(5)T11')
  security_warning(0);
else if (version == '12.1(5)T12')
  security_warning(0);
else if (version == '12.1(5)T13')
  security_warning(0);
else if (version == '12.1(5)T14')
  security_warning(0);
else if (version == '12.1(5)T15')
  security_warning(0);
else if (version == '12.1(5)T16')
  security_warning(0);
else if (version == '12.1(5)T17')
  security_warning(0);
else if (version == '12.1(5)T18')
  security_warning(0);
else if (version == '12.1(5)T19')
  security_warning(0);
else if (version == '12.1(5)T2')
  security_warning(0);
else if (version == '12.1(5)T3')
  security_warning(0);
else if (version == '12.1(5)T4')
  security_warning(0);
else if (version == '12.1(5)T5')
  security_warning(0);
else if (version == '12.1(5)T6')
  security_warning(0);
else if (version == '12.1(5)T7')
  security_warning(0);
else if (version == '12.1(5)T8')
  security_warning(0);
else if (version == '12.1(5)T8a')
  security_warning(0);
else if (version == '12.1(5)T8b')
  security_warning(0);
else if (version == '12.1(5)T8c')
  security_warning(0);
else if (version == '12.1(5)T9')
  security_warning(0);
else if (version == '12.1(5)XM')
  security_warning(0);
else if (version == '12.1(5)XM1')
  security_warning(0);
else if (version == '12.1(5)XM2')
  security_warning(0);
else if (version == '12.1(5)XM3')
  security_warning(0);
else if (version == '12.1(5)XM4')
  security_warning(0);
else if (version == '12.1(5)XM5')
  security_warning(0);
else if (version == '12.1(5)XM6')
  security_warning(0);
else if (version == '12.1(5)XM7')
  security_warning(0);
else if (version == '12.1(5)XM8')
  security_warning(0);
else if (version == '12.1(5)XR')
  security_warning(0);
else if (version == '12.1(5)XR1')
  security_warning(0);
else if (version == '12.1(5)XR2')
  security_warning(0);
else if (version == '12.1(5)XS')
  security_warning(0);
else if (version == '12.1(5)XS1')
  security_warning(0);
else if (version == '12.1(5)XS2')
  security_warning(0);
else if (version == '12.1(5)XS3')
  security_warning(0);
else if (version == '12.1(5)XS4')
  security_warning(0);
else if (version == '12.1(5)XS5')
  security_warning(0);
else if (version == '12.1(5)XU')
  security_warning(0);
else if (version == '12.1(5)XU1')
  security_warning(0);
else if (version == '12.1(5)XU2')
  security_warning(0);
else if (version == '12.1(5)XV')
  security_warning(0);
else if (version == '12.1(5)XV1')
  security_warning(0);
else if (version == '12.1(5)XV2')
  security_warning(0);
else if (version == '12.1(5)XV3')
  security_warning(0);
else if (version == '12.1(5)XV4')
  security_warning(0);
else if (version == '12.1(5)XX')
  security_warning(0);
else if (version == '12.1(5)XX1')
  security_warning(0);
else if (version == '12.1(5)XX2')
  security_warning(0);
else if (version == '12.1(5)XX3')
  security_warning(0);
else if (version == '12.1(5)YA')
  security_warning(0);
else if (version == '12.1(5)YA1')
  security_warning(0);
else if (version == '12.1(5)YA2')
  security_warning(0);
else if (version == '12.1(5)YB')
  security_warning(0);
else if (version == '12.1(5)YB1')
  security_warning(0);
else if (version == '12.1(5)YB2')
  security_warning(0);
else if (version == '12.1(5)YB3')
  security_warning(0);
else if (version == '12.1(5)YB4')
  security_warning(0);
else if (version == '12.1(5)YB5')
  security_warning(0);
else if (version == '12.1(5)YC')
  security_warning(0);
else if (version == '12.1(5)YC1')
  security_warning(0);
else if (version == '12.1(5)YC2')
  security_warning(0);
else if (version == '12.1(5)YC3')
  security_warning(0);
else if (version == '12.1(5)YD')
  security_warning(0);
else if (version == '12.1(5)YD1')
  security_warning(0);
else if (version == '12.1(5)YD2')
  security_warning(0);
else if (version == '12.1(5)YD3')
  security_warning(0);
else if (version == '12.1(5)YD4')
  security_warning(0);
else if (version == '12.1(5)YD5')
  security_warning(0);
else if (version == '12.1(5)YD6')
  security_warning(0);
else if (version == '12.1(6)')
  security_warning(0);
else if (version == '12.1(6a)')
  security_warning(0);
else if (version == '12.1(6)AA')
  security_warning(0);
else if (version == '12.1(6b)')
  security_warning(0);
else if (version == '12.1(6)DA')
  security_warning(0);
else if (version == '12.1(6)DA1')
  security_warning(0);
else if (version == '12.1(6)DA2')
  security_warning(0);
else if (version == '12.1(6)E')
  security_warning(0);
else if (version == '12.1(6)E1')
  security_warning(0);
else if (version == '12.1(6)E10')
  security_warning(0);
else if (version == '12.1(6)E11')
  security_warning(0);
else if (version == '12.1(6)E12')
  security_warning(0);
else if (version == '12.1(6)E13')
  security_warning(0);
else if (version == '12.1(6)E2')
  security_warning(0);
else if (version == '12.1(6)E3')
  security_warning(0);
else if (version == '12.1(6)E4')
  security_warning(0);
else if (version == '12.1(6)E5')
  security_warning(0);
else if (version == '12.1(6)E6')
  security_warning(0);
else if (version == '12.1(6)E7')
  security_warning(0);
else if (version == '12.1(6)E8')
  security_warning(0);
else if (version == '12.1(6)E9')
  security_warning(0);
else if (version == '12.1(6)EA1')
  security_warning(0);
else if (version == '12.1(6)EA1a')
  security_warning(0);
else if (version == '12.1(6)EC')
  security_warning(0);
else if (version == '12.1(6)EC1')
  security_warning(0);
else if (version == '12.1(6e)PE1')
  security_warning(0);
else if (version == '12.1(6)EX')
  security_warning(0);
else if (version == '12.1(6)EY')
  security_warning(0);
else if (version == '12.1(6)EY1')
  security_warning(0);
else if (version == '12.1(6)EZ')
  security_warning(0);
else if (version == '12.1(6)EZ1')
  security_warning(0);
else if (version == '12.1(6)EZ2')
  security_warning(0);
else if (version == '12.1(6)EZ3')
  security_warning(0);
else if (version == '12.1(6)EZ4')
  security_warning(0);
else if (version == '12.1(6)EZ5')
  security_warning(0);
else if (version == '12.1(6)EZ6')
  security_warning(0);
else if (version == '12.1(6)EZ7')
  security_warning(0);
else if (version == '12.1(6)EZ8')
  security_warning(0);
else if (version == '12.1(6r)DA')
  security_warning(0);
else if (version == '12.1(7)')
  security_warning(0);
else if (version == '12.1(7a)')
  security_warning(0);
else if (version == '12.1(7)AA')
  security_warning(0);
else if (version == '12.1(7a)E1')
  security_warning(0);
else if (version == '12.1(7a)E1a')
  security_warning(0);
else if (version == '12.1(7a)E2')
  security_warning(0);
else if (version == '12.1(7a)E3')
  security_warning(0);
else if (version == '12.1(7a)E4')
  security_warning(0);
else if (version == '12.1(7a)E5')
  security_warning(0);
else if (version == '12.1(7a)E6')
  security_warning(0);
else if (version == '12.1(7a)EY')
  security_warning(0);
else if (version == '12.1(7a)EY1')
  security_warning(0);
else if (version == '12.1(7a)EY2')
  security_warning(0);
else if (version == '12.1(7a)EY3')
  security_warning(0);
else if (version == '12.1(7b)')
  security_warning(0);
else if (version == '12.1(7c)')
  security_warning(0);
else if (version == '12.1(7)CX')
  security_warning(0);
else if (version == '12.1(7)CX1')
  security_warning(0);
else if (version == '12.1(7)DA')
  security_warning(0);
else if (version == '12.1(7)DA1')
  security_warning(0);
else if (version == '12.1(7)DA2')
  security_warning(0);
else if (version == '12.1(7)DA3')
  security_warning(0);
else if (version == '12.1(7)E')
  security_warning(0);
else if (version == '12.1(7)E0a')
  security_warning(0);
else if (version == '12.1(7)EC')
  security_warning(0);
else if (version == '12.1(8)')
  security_warning(0);
else if (version == '12.1(8a)')
  security_warning(0);
else if (version == '12.1(8)AA')
  security_warning(0);
else if (version == '12.1(8)AA1')
  security_warning(0);
else if (version == '12.1(8a)E')
  security_warning(0);
else if (version == '12.1(8a)E1')
  security_warning(0);
else if (version == '12.1(8a)E10102001')
  security_warning(0);
else if (version == '12.1(8a)E2')
  security_warning(0);
else if (version == '12.1(8a)E3')
  security_warning(0);
else if (version == '12.1(8a)E4')
  security_warning(0);
else if (version == '12.1(8a)E5')
  security_warning(0);
else if (version == '12.1(8a)EW')
  security_warning(0);
else if (version == '12.1(8a)EW1')
  security_warning(0);
else if (version == '12.1(8a)EX')
  security_warning(0);
else if (version == '12.1(8a)EX1')
  security_warning(0);
else if (version == '12.1(8b)')
  security_warning(0);
else if (version == '12.1(8b)E6')
  security_warning(0);
else if (version == '12.1(8b)E7')
  security_warning(0);
else if (version == '12.1(8b)E8')
  security_warning(0);
else if (version == '12.1(8b)E9')
  security_warning(0);
else if (version == '12.1(8b)EX2')
  security_warning(0);
else if (version == '12.1(8b)EX3')
  security_warning(0);
else if (version == '12.1(8b)EX4')
  security_warning(0);
else if (version == '12.1(8b)EX5')
  security_warning(0);
else if (version == '12.1(8c)')
  security_warning(0);
else if (version == '12.1(8)E')
  security_warning(0);
else if (version == '12.1(8)EA1')
  security_warning(0);
else if (version == '12.1(8)EA1b')
  security_warning(0);
else if (version == '12.1(8)EA1c')
  security_warning(0);
else if (version == '12.1(8)EC')
  security_warning(0);
else if (version == '12.1(8)EC1')
  security_warning(0);
else if (version == '12.1(8e)NAT001')
  security_warning(0);
else if (version == '12.1(8)EX')
  security_warning(0);
else if (version == '12.1(9)')
  security_warning(0);
else if (version == '12.1(9a)')
  security_warning(0);
else if (version == '12.1(9)E')
  security_warning(0);
else if (version == '12.1(9)E1')
  security_warning(0);
else if (version == '12.1(9)E2')
  security_warning(0);
else if (version == '12.1(9)E3')
  security_warning(0);
else if (version == '12.1(9)EA1')
  security_warning(0);
else if (version == '12.1(9)EA1a')
  security_warning(0);
else if (version == '12.1(9)EA1c')
  security_warning(0);
else if (version == '12.1(9)EA1d')
  security_warning(0);
else if (version == '12.1(9)EC')
  security_warning(0);
else if (version == '12.1(9)EC1')
  security_warning(0);
else if (version == '12.1(9)EX')
  security_warning(0);
else if (version == '12.1(9)EX1')
  security_warning(0);
else if (version == '12.1(9)EX2')
  security_warning(0);
else if (version == '12.1(9)EX3')
  security_warning(0);
else if (version == '12.1(9r)EX')
  security_warning(0);
else if (version == '12.2(1)')
  security_warning(0);
else if (version == '12.2(1a)')
  security_warning(0);
else if (version == '12.2(1a)XC')
  security_warning(0);
else if (version == '12.2(1a)XC1')
  security_warning(0);
else if (version == '12.2(1a)XC2')
  security_warning(0);
else if (version == '12.2(1a)XC3')
  security_warning(0);
else if (version == '12.2(1a)XC4')
  security_warning(0);
else if (version == '12.2(1a)XC5')
  security_warning(0);
else if (version == '12.2(1b)')
  security_warning(0);
else if (version == '12.2(1b)DA')
  security_warning(0);
else if (version == '12.2(1b)DA1')
  security_warning(0);
else if (version == '12.2(1c)')
  security_warning(0);
else if (version == '12.2(1d)')
  security_warning(0);
else if (version == '12.2(1)DX')
  security_warning(0);
else if (version == '12.2(1)DX1')
  security_warning(0);
else if (version == '12.2(1)MB1')
  security_warning(0);
else if (version == '12.2(1r)')
  security_warning(0);
else if (version == '12.2(1r)DD')
  security_warning(0);
else if (version == '12.2(1r)DD1')
  security_warning(0);
else if (version == '12.2(1r)T')
  security_warning(0);
else if (version == '12.2(1r)T1')
  security_warning(0);
else if (version == '12.2(1r)XA')
  security_warning(0);
else if (version == '12.2(1r)XE')
  security_warning(0);
else if (version == '12.2(1r)XE1')
  security_warning(0);
else if (version == '12.2(1r)XE2')
  security_warning(0);
else if (version == '12.2(1)XD')
  security_warning(0);
else if (version == '12.2(1)XD1')
  security_warning(0);
else if (version == '12.2(1)XD2')
  security_warning(0);
else if (version == '12.2(1)XD3')
  security_warning(0);
else if (version == '12.2(1)XD4')
  security_warning(0);
else if (version == '12.2(1)XE')
  security_warning(0);
else if (version == '12.2(1)XE1')
  security_warning(0);
else if (version == '12.2(1)XE2')
  security_warning(0);
else if (version == '12.2(1)XS')
  security_warning(0);
else if (version == '12.2(1)XS1')
  security_warning(0);
else if (version == '12.2(1)XS1a')
  security_warning(0);
else if (version == '12.2(1)XS2')
  security_warning(0);
else if (version == '12.2(2)B')
  security_warning(0);
else if (version == '12.2(2)B1')
  security_warning(0);
else if (version == '12.2(2)B2')
  security_warning(0);
else if (version == '12.2(2)B3')
  security_warning(0);
else if (version == '12.2(2)B4')
  security_warning(0);
else if (version == '12.2(2)B5')
  security_warning(0);
else if (version == '12.2(2)B6')
  security_warning(0);
else if (version == '12.2(2)B7')
  security_warning(0);
else if (version == '12.2(2b)REG1')
  security_warning(0);
else if (version == '12.2(2)DD')
  security_warning(0);
else if (version == '12.2(2)DD1')
  security_warning(0);
else if (version == '12.2(2)DD2')
  security_warning(0);
else if (version == '12.2(2)DD3')
  security_warning(0);
else if (version == '12.2(2)DD4')
  security_warning(0);
else if (version == '12.2(2)DX')
  security_warning(0);
else if (version == '12.2(2)DX1')
  security_warning(0);
else if (version == '12.2(2)DX2')
  security_warning(0);
else if (version == '12.2(2)DX3')
  security_warning(0);
else if (version == '12.2(2r)B7')
  security_warning(0);
else if (version == '12.2(2r)B8')
  security_warning(0);
else if (version == '12.2(2r)DD')
  security_warning(0);
else if (version == '12.2(2r)T')
  security_warning(0);
else if (version == '12.2(2r)T1')
  security_warning(0);
else if (version == '12.2(2r)T2')
  security_warning(0);
else if (version == '12.2(2r)XA')
  security_warning(0);
else if (version == '12.2(2r)XB')
  security_warning(0);
else if (version == '12.2(2r)XB5')
  security_warning(0);
else if (version == '12.2(2r)XT')
  security_warning(0);
else if (version == '12.2(2)T')
  security_warning(0);
else if (version == '12.2(2)T1')
  security_warning(0);
else if (version == '12.2(2)T2')
  security_warning(0);
else if (version == '12.2(2)T3')
  security_warning(0);
else if (version == '12.2(2)T4')
  security_warning(0);
else if (version == '12.2(2)XA')
  security_warning(0);
else if (version == '12.2(2)XA1')
  security_warning(0);
else if (version == '12.2(2)XA2')
  security_warning(0);
else if (version == '12.2(2)XA3')
  security_warning(0);
else if (version == '12.2(2)XA4')
  security_warning(0);
else if (version == '12.2(2)XA5')
  security_warning(0);
else if (version == '12.2(2)XB')
  security_warning(0);
else if (version == '12.2(2)XB1')
  security_warning(0);
else if (version == '12.2(2)XB10')
  security_warning(0);
else if (version == '12.2(2)XB11')
  security_warning(0);
else if (version == '12.2(2)XB12')
  security_warning(0);
else if (version == '12.2(2)XB14')
  security_warning(0);
else if (version == '12.2(2)XB15')
  security_warning(0);
else if (version == '12.2(2)XB16')
  security_warning(0);
else if (version == '12.2(2)XB17')
  security_warning(0);
else if (version == '12.2(2)XB18')
  security_warning(0);
else if (version == '12.2(2)XB2')
  security_warning(0);
else if (version == '12.2(2)XB3')
  security_warning(0);
else if (version == '12.2(2)XB4')
  security_warning(0);
else if (version == '12.2(2)XB4b')
  security_warning(0);
else if (version == '12.2(2)XB5')
  security_warning(0);
else if (version == '12.2(2)XB6')
  security_warning(0);
else if (version == '12.2(2)XB6a')
  security_warning(0);
else if (version == '12.2(2)XB6b')
  security_warning(0);
else if (version == '12.2(2)XB6c')
  security_warning(0);
else if (version == '12.2(2)XB6d')
  security_warning(0);
else if (version == '12.2(2)XB7')
  security_warning(0);
else if (version == '12.2(2)XB8')
  security_warning(0);
else if (version == '12.2(2)XB9')
  security_warning(0);
else if (version == '12.2(2)XC')
  security_warning(0);
else if (version == '12.2(2)XC1')
  security_warning(0);
else if (version == '12.2(2)XC2')
  security_warning(0);
else if (version == '12.2(2)XC3')
  security_warning(0);
else if (version == '12.2(2)XC4')
  security_warning(0);
else if (version == '12.2(2)XC5')
  security_warning(0);
else if (version == '12.2(2)XC6')
  security_warning(0);
else if (version == '12.2(2)XC7')
  security_warning(0);
else if (version == '12.2(2)XF')
  security_warning(0);
else if (version == '12.2(2)XF1')
  security_warning(0);
else if (version == '12.2(2)XF2')
  security_warning(0);
else if (version == '12.2(2)XG')
  security_warning(0);
else if (version == '12.2(2)XG1')
  security_warning(0);
else if (version == '12.2(2)XH')
  security_warning(0);
else if (version == '12.2(2)XH1')
  security_warning(0);
else if (version == '12.2(2)XH2')
  security_warning(0);
else if (version == '12.2(2)XI')
  security_warning(0);
else if (version == '12.2(2)XI1')
  security_warning(0);
else if (version == '12.2(2)XI2')
  security_warning(0);
else if (version == '12.2(2)XJ')
  security_warning(0);
else if (version == '12.2(2)XK')
  security_warning(0);
else if (version == '12.2(2)XK1')
  security_warning(0);
else if (version == '12.2(2)XK2')
  security_warning(0);
else if (version == '12.2(2)XK3')
  security_warning(0);
else if (version == '12.2(2)XN')
  security_warning(0);
else if (version == '12.2(2)XQ')
  security_warning(0);
else if (version == '12.2(2)XQ1')
  security_warning(0);
else if (version == '12.2(2)XR')
  security_warning(0);
else if (version == '12.2(2)XT')
  security_warning(0);
else if (version == '12.2(2)XT1')
  security_warning(0);
else if (version == '12.2(2)XT2')
  security_warning(0);
else if (version == '12.2(2)XT3')
  security_warning(0);
else if (version == '12.2(2)XU')
  security_warning(0);
else if (version == '12.2(2)XU1')
  security_warning(0);
else if (version == '12.2(2)XU2')
  security_warning(0);
else if (version == '12.2(2)XU3')
  security_warning(0);
else if (version == '12.2(2)XU4')
  security_warning(0);
else if (version == '12.2(2)YC')
  security_warning(0);
else if (version == '12.2(2)YC1')
  security_warning(0);
else if (version == '12.2(2)YC2')
  security_warning(0);
else if (version == '12.2(2)YC3')
  security_warning(0);
else if (version == '12.2(2)YC4')
  security_warning(0);
else if (version == '12.2(2)YK')
  security_warning(0);
else if (version == '12.2(2)YK1')
  security_warning(0);
else if (version == '12.2(3)')
  security_warning(0);
else if (version == '12.2(3a)')
  security_warning(0);
else if (version == '12.2(3b)')
  security_warning(0);
else if (version == '12.2(3c)')
  security_warning(0);
else if (version == '12.2(3d)')
  security_warning(0);
else if (version == '12.2(3e)')
  security_warning(0);
else if (version == '12.2(3f)')
  security_warning(0);
else if (version == '12.2(3g)')
  security_warning(0);
else if (version == '12.2(4)MX')
  security_warning(0);
else if (version == '12.2(4)MX1')
  security_warning(0);
else if (version == '12.2(4)MX2')
  security_warning(0);
else if (version == '12.2(4r)T')
  security_warning(0);
else if (version == '12.2(4r)T1')
  security_warning(0);
else if (version == '12.2(4r)XL')
  security_warning(0);
else if (version == '12.2(4r)XT')
  security_warning(0);
else if (version == '12.2(4r)XT1')
  security_warning(0);
else if (version == '12.2(4r)XT2')
  security_warning(0);
else if (version == '12.2(4r)XT3')
  security_warning(0);
else if (version == '12.2(4r)XT4')
  security_warning(0);
else if (version == '12.2(4)XR')
  security_warning(0);
else if (version == '12.2(7r)EY')
  security_warning(0);
else if (version == '12.2(7r)XM')
  security_warning(0);
else if (version == '12.2(7r)XM1')
  security_warning(0);
else if (version == '12.2(7r)XM2')
  security_warning(0);
else if (version == '12.2(7r)XM3')
  security_warning(0);
else if (version == '12.2(7r)XM4')
  security_warning(0);
else if (version == '12.2(7r)XM5')
  security_warning(0);
else if (version == '12.2(99r)B')
  security_warning(0);
else if (version == '12.9(9)S0225')
  security_warning(0);
else
  audit(AUDIT_HOST_NOT, 'affected');
