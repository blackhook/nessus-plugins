#TRUSTED 470883df9045c32ff9c35239a1fb83e4f4154158f44601c2f220f3fa52af8f64937de04c0995d661e987ff156b2164cd59d5ee4fd4ebaa7b8fa3980ff325816ba41d69f1fa368757dc37b333a56301e5944b2846223138a9f3ee9890b7df1c19f74c9cb70c8096ecc1d351d3de03bc84acb390109fbc4e18485534fde357589d34502b8e23cbe1a1f0447706b3b144957e8ded4c08fd158e3aa47f8e7facbcd7308f48d528896eb2147ded8a4aff0f994ad088bc013b07c09c2f1de009adc85fc8da63009c08c42520d51d583cb3919cc5ebdc00fcf86ac448d8f7d8655b9307653ba003f2e3441ad57d982e2c775b630b50448c89408d6417189c1816b968bef364216d1fa0e847d5e46673ac10b5d6c1a146ea13137a122831bb578804496e925f904746368558ec5c2ebc2aefbfc0079f3bcd59ac2858b940177774309828e71fb2ea0b45b273ddb787636debc2abeecfd258798ac5a6ee9e3594fb82d2b33ffa2d8cdb2810ee769fd3d2a08d4312793c743e2079138e0b119f6b772a8935f2c5225109cfb03c7d448ddd82b6d1d43b926253b3de74ed1ee63d1a983f409a217de2d7061ca3853d14c5bec50dbd6d6474364d199924f28df74de041107406ce723e0d626e10695e126de6810c0d1cdb2b070c9c18ec35362b5426e0ad3ec4ccbdf94d01e7f48152efea5e6c2e6e215d32e8243c26ec4d4c3f75b402dbf53a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76508);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-3822");
  script_bugtraq_id(68553);
  script_xref(name:"JSA", value:"JSA10641");

  script_name(english:"Juniper Junos SRX Series NAT IPv6 to IPv4 Remote DoS (JSA10641)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a denial of service
vulnerability. A remote attacker, by sending a specially crafted
packet to an SRX series device, can crash the 'flowd' process when the
packet is translated from IPv6 to IPv4.

Note that this issue only affects devices with NAT protocol
translation from IPv6 to IPv4 enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10641");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10641.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

# if (compare_build_dates(build_date, '2014-07-31') >= 0)
#  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['11.4']    = '11.4R8';
fixes['12.1']    = '12.1R5';
fixes['12.1X44'] = '12.1X44-D20';
fixes['12.1X45'] = '12.1X45-D15';
fixes['12.1X46'] = '12.1X46-D10';
fixes['12.1X47'] = '12.1X47-D10';
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if NAT protocol translation from IPv6 to IPv4 is enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set services nat .* translation-type basic-nat-pt";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT,
      'affected because NAT protocol translation from IPv6 to IPv4 is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
