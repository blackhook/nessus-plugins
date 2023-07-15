#TRUSTED 3844fe1b54bbe30afd4f212f7bfe3cd958149dd57c96dcfd30118deb09e4e6d14e20b93f4eb47619a6492fd7d716751922af11430c1c80dd7c747c576fe809e883179c39bc68ea8cd5f5a2d09a33fc5aacbf12a3b735a5afb701a7b6263e0f699f6de61e611ed8773abcb11f7ea174cf4c79e4c9f0a009f9cd6c749e3accae13cae771530b38ae8bd34afaf623ed68a29906fb1745973cf8a428e42fb5ea28e95b029be474a96985a7bd2175327e29f3f6080bbd1800d7f7fac5eab720f48dbd5e294d3bc9e0bf469a139444a05e5438d2d8170a19cb813f5697c3e2d7d6863b94b944d335dd8876bc5d4e16a42b9308e10d85909139406203e6fd48010ae4b71b8db4e2bfe281bc22bc63d57af6a5908969764573bf19fd9804aff59a795eb54d9bc6a3562fec347c8562105ad81f1e7f206b40feb02863046d5acb1cc9e0cc55e329c6fc6c61472a38f6a39ab6678bcafa812afce2f4bf9eb2088dd234b86d869949baadf37c450c783c6754a66c3bb365d5ac4cb9a0c20b351b7d7bd8b6af71f8d4509b1ea6816fe2be8f6f01a8ee2d2d731fc774052c07b44141e6af92312bbb04ee4d01afc136fc17e93d92fc292cb77aba61d2a624675cc6b566ce5863a18b323674ef9ed973512c7e161e657731560f89418ec624ae220179be6b24dd552b95ae7c64156516a47bbbf51b1969f16b1070081cdacb1f6f0bb4226eba9f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85124);
  script_version("1.15");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0681");
  script_bugtraq_id(75995);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts66733");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150722-tftp");

  script_name(english:"Cisco IOS Software TFTP DoS (cisco-sa-20150722-tftp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the TFTP server functionality due to incorrect management of memory
when handling TFTP requests. A remote, unauthenticated attacker can
exploit this by sending a large amount of TFTP requests to cause the
remote device to reload or hang, resulting in a denial of service
condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150722-tftp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f445f230");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCts66733");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150722-tftp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/30");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

app = "Cisco IOS";
cbi = "CSCts66733";
fixed_ver = NULL;

if (
  ver == "12.2(32.8.11)SX507" || # Bug report
  ver == "12.2(44)SQ1" || # Vulnerability Alert
  ver == "12.2(50)SY" ||
  ver == "12.2(50)SY1" ||
  ver == "12.2(50)SY2" ||
  ver == "12.2(50)SY3" ||
  ver == "12.2(50)SY4" ||
  ver == "12.2(33)XN" ||
  ver == "12.2(33)XN1" ||
  ver == "12.4(24)GC1" ||
  ver == "12.4(24)GC3" ||
  ver == "12.4(24)GC3a" ||
  ver == "12.4(25e)JAM1" ||
  ver == "12.4(25e)JAO5m" ||
  ver == "12.4(23)JY" ||
  ver == "12.4(24)T" ||
  ver == "15.0(2)ED1" ||
  ver == "15.0(2)EY3" ||
  ver == "15.0(1)M1" ||
  ver == "15.0(1)M4" ||
  ver == "15.0(1)SY" ||
  ver == "15.0(1)XA" ||
  ver == "15.0(1)XA2" ||
  ver == "15.0(1)XA3" ||
  ver == "15.0(1)XA4" ||
  ver == "15.0(1)XA5" ||
  ver == "15.1(3)SVF4a" ||
  ver == "15.1(3)SVF4b" ||
  ver == "15.1(3)SVG3b" ||
  ver == "15.1(3)SVH2" ||
  ver == "15.1(3)SVI" ||
  ver == "15.1(3)SVI1" ||
  ver == "15.1(1)T" ||
  ver == "15.1(1)T1" ||
  ver == "15.1(1)T2" ||
  ver == "15.1(2)T" ||
  ver == "15.1(2)T0a" ||
  ver == "15.1(2)T1" ||
  ver == "15.1(2)T2" ||
  ver == "15.1(2)T2a" ||
  ver == "15.1(3)T" ||
  ver == "15.2(2)JB1" ||
  ver == "15.2(1)SC1a" ||
  ver == "15.2(1)SC2" ||
  ver == "15.2(1)SD6a" ||
  ver == "15.2(1)SD8" ||
  ver == "15.2(1)S2" || # IOS-XE to IOS Mapping using Internet resources
  ver == "15.2(1)S1" ||
  ver == "15.2(1)S" ||
  ver == "15.1(3)S6" ||
  ver == "15.1(3)S5" ||
  ver == "15.1(3)S4" ||
  ver == "15.1(3)S3" ||
  ver == "15.1(3)S2" ||
  ver == "15.1(3)S1" ||
  ver == "15.1(3)S0a" ||
  ver == "15.1(3)S" ||
  ver == "15.1(2)S2" ||
  ver == "15.1(2)S1" ||
  ver == "15.1(2)S" ||
  ver == "15.1(1)S2" ||
  ver == "15.1(1)S1" ||
  ver == "15.1(1)S" ||
  ver == "15.0(1)S4a" ||
  ver == "15.0(1)S4" ||
  ver == "15.0(1)S3" ||
  ver == "15.0(1)S2" ||
  ver == "15.0(1)S1" ||
  ver == "15.0(1)S" ||
  ver == "12.2(33)XNF2" ||
  ver == "12.2(33)XNF1" ||
  ver == "12.2(33)XNF" ||
  ver == "12.2(33)XNE2" ||
  ver == "12.2(33)XNE1" ||
  ver == "12.2(33)XNE" ||
  ver == "15.0(1)EX" || # IOS-XE to IOS mapping using info in cisco_ios_xe_version.nasl
  ver == "15.0(1)EX1" ||
  ver == "15.0(1)EX2" ||
  ver == "15.0(1)EX3" ||
  ver == "15.0(1)XO" ||
  ver == "15.0(1)XO1" ||
  ver == "15.0(2)SG" ||
  ver == "15.0(2)SG1" ||
  ver == "15.0(2)XO" ||
  ver == "15.1(1)SG" ||
  ver == "15.1(1)SG1" ||
  ver == "15.2(1)S1" ||
  ver == "15.2(1)S2" ||
  # Added due to VULN-81062
  ver == "122-55.SE10" ||
  ver == "122-33.SXI14" ||
  ver == "15.0(2)SE7" ||
  ver == "15.1(4)M10" ||
  ver == "15.0(2)SG10" ||
  # Added due to VULN-81062-2
  ver == "12.2(55)SE10" ||
  ver == "12.2(33)SXI14"
)
  fixed_ver = "Refer to vendor.";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

flag     = TRUE;
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;
  # TFTP Check
  #  Router#show running-config | include ^tftp-server
  #  tftp-server flash:c2800nm-adventerprisek9-mz.124-1
  #  tftp-server flash:
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"tftp-server flash:", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}
else override = TRUE;

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because TFTP is not enabled");

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
