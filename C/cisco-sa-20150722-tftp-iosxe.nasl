#TRUSTED 4c9db665356ef741e09ff20bcc9d946e66e00dca77b4cf619253f59c54821bf9881715c3f23d495a01218480ade6eaf7176918d9482a2230f01cc06d894a0de2bc8fd90bd6dec74812f79ff6129722ddd4240798f84fa9f10b1281df7a1ba95be74094b7938805ad195363d978a8bcc1d166a18e68cb03efa01c2467b3eacb7e678cf13039cc6c3818d6232fb3fb2483662c6e37c7d0f0d56395fdab10915f2bfe2a72fbb160a5d42cbd76a9a7c91eb9e85903dda80488091c8f027a0defabe2fdeb0371e36e91802381b7241a04203d3cf44541f91e341d32dc88a1374324ad73e3771cb1d5eb391e11b10f28909a6bc393f89e4b9deb34d5ef2ccb6fcbc0efddad1cd11ad5395842fd52c84fbbfe6434674e57e271fb387bb808277b1bf0d766e2b937444327941d8b31b3e29dd089b92eb18aef42267915a649d72523cd7d10d10942b9edef2bc50852b05ff00b89f67256970320604acdf5f0816826078dc7169995a554acb1f6e6993000aa1e6b1918cbc90e60d28ccfafa2fba117d2145b452ad55053519d99bd4b8f7ebfa9db8be18b273373eeffb2ae0de761b7b3da37c7487b00c779bbb24a7ec0e60b6455d01ea364f5c612c6f4a44e0ddff9d7bbb4cc4ef2d720880a352c51483fc663106f9a00c351a445262aa3b4e48f4cd94eb61109767e9c05c9e019e9725fee23d925d00d0894a46442f59c7971b6833368
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85125);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0681");
  script_bugtraq_id(75995);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts66733");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150722-tftp");

  script_name(english:"Cisco IOS XE Software TFTP DoS (cisco-sa-20150722-tftp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the TFTP server functionality due to incorrect
management of memory when handling TFTP requests. A remote,
unauthenticated attacker can exploit this by sending a large amount of
TFTP requests to cause the remote device to reload or hang, resulting
in a denial of service condition.");
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCts66733";
fixed_ver = NULL;

if (
  ver =~ "^2\.[56]\." ||
  ver =~ "^3\.[1-5]\.\d+[a-z]?S$"
) fixed_ver = "3.6.0S";

if (
  ver =~ "^3\.[1-3]\.\d+[a-z]?SG$"
)  fixed_ver = "3.4.0SG";

if (
  ver =~ "^3\.2\.\d+[a-z]?SE$"
)  fixed_ver = "3.3.0SE";

if (
  ver =~ "^3\.2\.\d+[a-z]?XO$"
)  fixed_ver = "3.3.0XO";

if (
  ver =~ "^3\.[2-4]\.\d+[a-z]?SQ$"
)  fixed_ver = "Contact Vendor";

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
