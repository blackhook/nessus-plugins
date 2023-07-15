#TRUSTED 2f14a898cc8ac1e6751fc85228b86f16bfcd71415c614fa21c589b8a592c2dcfee33e9c4d22acea4908bdce7c6e2c131c353dd2f909330969185f49c3398172eb39c50f73107732d5e9d32e45804f5f1775e5e219566af21e04435b84cbe85d20a6149838c8649d7eac74741d70eb16c36518fb34cf3a16b128e355acdcd7cc2943d675baa229f082706171c0eb78c3cd91e596b18b22ee452c9bf6870c8eba5538425a00aa314b94134f59b0ea42ace05f3c7828d9d3d5ff690b3b5d1ceb4e195ea85ba454e5082d6adcf4131843ec5dc52d6ac723697375c91fd5a8ed327c2e016fa0195dec86a5d8440c31b65f00ecce377cd123dd841d1ba685c3d32d5cea641de89f7d3877a8ab9d51b796f93af92950df2ea4c0625868b62895cdd76ac38c1b7c3dc4d82a3e24c72707e5a38b5c2d25bd0dd9b63f11d2124242b34de42cd3ed7be2c372d52bfd3c379c7ee4fda09501929ca13cf46619911362398b88440081840f86e02aecfd0862a56d6506505c28fe98cb0d3c1e13288c2e121f55bde522267e48c9e33df35b7bc0e44df9bdc8f8f1d24cfa9b284a96d9e91441b6e3742f3e806fa56c89bc4f229c231045bb94ee35bdfc9298e18cf7593dc361d032c88dff9e52e89a7ac44189c082544acbc3c417b78043287b125ea622bb774aec7c00d6a371ac0fe164544f1f90eec873ba933bff51ce1a373a88b06ee50c57f
#
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68961);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/26");

  script_cve_id("CVE-2008-3819");
  script_bugtraq_id(33152);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsj70093");
  script_xref(name:"IAVT", value:"2009-T-0004-S");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20090107-gss");

  script_name(english:"Cisco Global Site Selector Appliances DNS Vulnerability (cisco-sa-20090107-gss)");
  script_summary(english:"Checks the GSS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Application Control Engine Global Site Selector (GSS)
contains a denial of service (DoS) issue when processing specific Domain
Name System (DNS) requests.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20090107-gss
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0686f1ca");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090107-gss.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:gss_4480_global_site_selector");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:gss_4490_global_site_selector");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:gss_4491_global_site_selector");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:gss_4492r_global_site_selector");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/18");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_gss_version.nasl");
  script_require_keys("Host/Cisco/GSS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
report_extras = "";

model = get_kb_item_or_exit("Host/Cisco/GSS/model");
version = get_kb_item_or_exit("Host/Cisco/GSS/Version");

if ( (model != "4480") && (model != "4490") && (model != "4491") && (model != "4492r") )
  audit(AUDIT_HOST_NOT, "GSS model 4480/4490/4491/4492r");

if ( version =~ "^1\." ) flag++;
if ( version =~ "^2\." ) flag++;

if (flag)
{
  if (get_kb_item("Host/local_checks_enabled"))
  {
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running", "show running");
    if (check_cisco_result(buf))
    {
      if ( (preg(pattern:"cnr enable", multiline:TRUE, string:buf)) && (!preg(pattern:"no cnr enable", multiline:TRUE, string:buf)) )
      {
        flag = 0;
      }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
