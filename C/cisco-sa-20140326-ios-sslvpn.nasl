#TRUSTED 6b3a0597cbe28bb290b1361693c3213824dd54d5165602d717194c3bb4390e22cfb8f78203835d658d2df6be9f75b957d9988ed5b6ae10e1e5b4c49e42f8f152a55430720af82cffb1a5cdcc4c330fe15b29ed794c33aea1f4bc793921ee1682e69c76e9045486671d02ac564a8ea2c31785f64c453b7b07280561146e7a39757c104d9baa30b04d9e9994ab096e35b11dddbb641e18823c852f091ac8a35b3b547bce489af2b4ff99edd433ce61efe2437245813de45e447338c41c503f5d88a3fb4632c7b0b57463c4e653dd5b4b7cda21cb29db8415523c4ba2d77d22d5f054ed4c9e205653bcab30ee0ace4e50a326e93dd10e7539311632bfad1b1088dd6ab033ce9b95a65618eb6d63680af0a4a2b01925638f5e6d683cb1b274a88c3bf3dff2a960537fd67783df0154b92a9745a93ae40c0356d344b245e8238c174ef9aeff4f8862241776ac6ae1cbbc64e10019dff9d59cc2ccf85c8830d9496e913563d22d2ad141642a90e35d1b794ed5199611dd6088e418a7cb61fc2f5bdbc204e58361045652d8cebfc75f3fefc13acc2da2786d78add032a324acb10c1f3927ebacccb54c1e022c3d946f3081aab0f82787b913019d0e05e198f519a1fea9c5fb1ce212fb2eb4c4c1d172848f103b59a711cf1697e592e75a708bddfe420156b202e8822f813d968649ebe7d0032a6403290e89a234557e054fe8685f30ad
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73342);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-2112");
  script_bugtraq_id(66462);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf51357");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ios-sslvpn");

  script_name(english:"Cisco IOS Software SSL VPN Denial of Service (cisco-sa-20140326-ios-sslvpn)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability due to improper handling of certain, unspecified types
of HTTP requests in the SSL VPN subsystem. An unauthenticated, remote
attacker could potentially exploit this issue by sending specially
crafted HTTP requests resulting in a denial of service.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ios-sslvpn
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b0c3f17");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33350");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-ios-sslvpn.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

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

flag = 0;
override = 0;
report = "";
fixed_ver = "";
cbi = "CSCuf51357";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

#15.1GC
if (ver == "15.1(2)GC" ||  ver == "15.1(2)GC1" ||  ver == "15.1(2)GC2" ||  ver == "15.1(4)GC" ||  ver == "15.1(4)GC1" ||  ver == "15.1(4)GC2")
  fixed_ver = "15.1(4)M7";
#15.1M
else if (ver == "15.1(4)M" ||  ver == "15.1(4)M0a" ||  ver == "15.1(4)M0b" ||  ver == "15.1(4)M1" ||  ver == "15.1(4)M2" ||  ver == "15.1(4)M3" ||  ver == "15.1(4)M3a" ||  ver == "15.1(4)M4" ||  ver == "15.1(4)M5" ||  ver == "15.1(4)M6")
  fixed_ver = "15.1(4)M7";
#15.1T
else if (ver == "15.1(2)T" ||  ver == "15.1(2)T0a" ||  ver == "15.1(2)T1" ||  ver == "15.1(2)T2" ||  ver == "15.1(2)T2a" ||  ver == "15.1(2)T3" ||  ver == "15.1(2)T4" ||  ver == "15.1(2)T5" ||  ver == "15.1(3)T" ||  ver == "15.1(3)T1" ||  ver == "15.1(3)T2" ||  ver == "15.1(3)T3" ||  ver == "15.1(3)T4")
  fixed_ver = "15.1(4)M7";
#15.1XB
else if (ver == "15.1(4)XB4" ||  ver == "15.1(4)XB5" ||  ver == "15.1(4)XB5a" ||  ver == "15.1(4)XB6" ||  ver == "15.1(4)XB7" ||  ver == "15.1(4)XB8" ||  ver == "15.1(4)XB8a")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2GC
else if (ver == "15.2(1)GC" ||  ver == "15.2(1)GC1" ||  ver == "15.2(1)GC2" ||  ver == "15.2(2)GC" ||  ver == "15.2(3)GC" ||  ver == "15.2(3)GC1" ||  ver == "15.2(4)GC")
  fixed_ver = "15.2(4)GC1";
#15.2GCA
else if (ver == "15.2(3)GCA" ||  ver == "15.2(3)GCA1")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2M
else if (ver == "15.2(4)M" ||  ver == "15.2(4)M1" ||  ver == "15.2(4)M2" ||  ver == "15.2(4)M3" ||  ver == "15.2(4)M4" ||  ver == "15.2(4)M5")
  fixed_ver = "15.2(4)M6";
#15.2T
else if (ver == "15.2(1)T" ||  ver == "15.2(1)T1" ||  ver == "15.2(1)T2" ||  ver == "15.2(1)T3" ||  ver == "15.2(1)T3a" ||  ver == "15.2(1)T4" ||  ver == "15.2(2)T" ||  ver == "15.2(2)T1" ||  ver == "15.2(2)T2" ||  ver == "15.2(2)T3" ||  ver == "15.2(2)T4" ||  ver == "15.2(3)T" ||  ver == "15.2(3)T1" ||  ver == "15.2(3)T2" ||  ver == "15.2(3)T3" ||  ver == "15.2(3)T4")
  fixed_ver = "15.2(4)M6";
#15.2XA
else if (ver == "15.2(3)XA")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2XB
else if (ver == "15.2(4)XB10")
  fixed_ver = "Refer to the vendor for a fix.";
#15.3M
else if (ver == "15.3(3)M" ||  ver == "15.3(3)M1")
  fixed_ver = "15.3(3)M2";
#15.3T
else if (ver == "15.3(1)T" ||  ver == "15.3(1)T1" ||  ver == "15.3(1)T2" ||  ver == "15.3(1)T3" ||  ver == "15.3(2)T" ||  ver == "15.3(2)T1" ||  ver == "15.3(2)T2")
  fixed_ver = "15.3(1)T4 / 15.3(2)T3";
#15.4CG
else if (ver == "15.4(1)CG")
  fixed_ver = "Refer to the vendor for a fix.";
#15.4S
else if (ver == "15.4(1)S")
  fixed_ver = "15.4(1)S1";
#15.4T
else if (ver == "15.4(1)T")
  fixed_ver = "15.4(1)T1";

if (fixed_ver) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      m = eregmatch(pattern:"webvpn gateway([^!]+)!", string:buf);
      if ( (!isnull(m)) && ("inservice" >< m[1]) ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
