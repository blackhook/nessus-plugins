#TRUSTED 0b5f01c845c9a8b612742cf35eb7979fa1dffa513e626b01ca4c40bbe116fe906ec406675471330ba890007cda116bc2c919a4dbd7f65a3031d85961a6cda355f37613915bd24c4060c68cc20d5f67251603f5410b3620db94741c2c0203a6a077fd1dc7eaaae0a38907270a6a5ea174c32ee448186176c830849cef6baa1deeca113c86aff700c78b47f0797af44d9a1773eac19aa5fef516030244bf5da8f6d384283250b757bc3b62df649b4530bef90a49d3f95c3bd58457647cd227cf1b78c295c4e34e300a9feefa175c4bae5ba95fbcd98ffb411374d38da86702ea7dea7b8f5abc3a86cf3c4f41ab7fd8b5fd86832f21d29075c2d8684ad8dc7c8b66faa9e9e6be1af56ae76a3b6a6b33b461cb5bcca611d196d5bae053e8b55f42531d9fd54529081eecbd94a105eb2538b30962dee29409694a6f85cb6ce6bd5e78bb8ef4142feee29e6bf8bb5bbe749513753c96089e9ac4069e763cf1d970421e0728ea536cc1242c73e45f7a62053d4f922737e9681de36040874d3b284608966c24f429e4f4995333f95f01b41e99518adc62772ea0e550615bf30ea599435232fc4ca581f56605d51351ae3d1b036c5628ee6b128a4b23e9f08282edd806a75a7be074b87e36f686c8b750163583ab2990174032782f8e02f3cb2b880c318c1dfb4f7617d770d5ef3aa35ed27cbd2a82307db6a694efaece195941a22735c1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69335);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2008-2060");
  script_bugtraq_id(29791);
  script_xref(name:"CISCO-BUG-ID", value:"CSCso64762");
  script_xref(name:"IAVT", value:"2008-T-0030-S");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20080618-ips");

  script_name(english:"Cisco Intrusion Prevention System Jumbo Frame Denial of Service (cisco-sa-20080618-ips)");
  script_summary(english:"Checks IPS version");

  script_set_attribute(attribute:"synopsis", value:"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of the Cisco
Intrusion Prevention System Software running on the remote host may be
vulnerable to a denial of service (DoS) attack caused by a kernel panic.
This is due to the handling of jumbo Ethernet frames when gigabit
network interfaces are installed and are deployed in inline mode."
  );
  # https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20080618-ips.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84dc8ff1");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20080618-ips."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:intrusion_prevention_system");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ips_version.nasl");
  script_require_keys("Host/Cisco/IPS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");


##
# Compares two strings representing versions. (assumes the strings are "." delimited.
#
# @param fix     The second version string.
# @param ver     The first version string.
#
# @return -1 if ver < fix, 0 if ver == fix, or 1 if ver > fix.
##
function ips_ver_compare(fix, ver)
{
  local_var ffield, vfield, flen, vlen, len, i;
  # replace ( and ) with dots to make comparisons more accurate
  ver = ereg_replace(pattern:'[()]', replace:".", string:ver);
  fix = ereg_replace(pattern:'[()]', replace:".", string:fix);
  # Break apart the version strings into numeric fields.
  ver = split(ver, sep:'.', keep:FALSE);
  fix = split(fix, sep:'.', keep:FALSE);
  # Both versions must have the same number of fields when
  # when doing a strict comparison.
  vlen = max_index(ver);
  flen = max_index(fix);
  len = vlen;
  if (flen > len) len = flen;
  # Compare each pair of fields in the version strings.
  for (i = 0; i < len; i++)
  {
    if (i >= vlen) vfield = 0;
    else vfield = ver[i];
    if (i >= flen) ffield = 0;
    else ffield = fix[i];
    if ( (int(vfield) == vfield) && (int(ffield) == ffield) )
    {
      vfield = int(ver[i]);
      ffield = int(fix[i]);
    }
    if (vfield < ffield) return -1;
    if (vfield > ffield) return 1;
  }
  return 0;
}

ver = get_kb_item_or_exit('Host/Cisco/IPS/Version');
model = get_kb_item_or_exit('Host/Cisco/IPS/Model');
display_fix = "";

if (model =~ "4235" ||
    model =~ "4240" ||
    model =~ "4250" ||
    model =~ "4250SX" ||
    model =~ "4250TX" ||
    model =~ "4250XL" ||
    model =~ "4255" ||
    model =~ "4260" ||
    model =~ "4270")
{
  if ( (ver =~ "^5\.") && (ips_ver_compare(ver:ver, fix:"5.1(8)E2") < 0) )
    display_fix = "5.1(8)E2";
  if ( (ver =~ "^6\.") && (ips_ver_compare(ver:ver, fix:"6.0(5)E2") < 0) )
    display_fix = "6.0(5)E2";
}

if (display_fix == "")
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IPS', ver);

flag = 1;
override = 0;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_interfaces", "show interfaces");
  if (check_cisco_result(buf))
  {
    if (preg(pattern:"Inline Mode = Paired with", multiline:TRUE, string:buf)) { flag = 1; }
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");

