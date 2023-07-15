#TRUSTED 8c58f90475fad8010aa1b21d2c47ca86b914dff77c54ef82371c4baf47965ac8e35eaa2cd6353cbf89f4692ad0d357ba15c58e214944cc1007f062ac39144cfb503a1bd4bbb54d060f8eb0760c72480faa6e30928cebb67d46d43297376a3f9b76d2fdd806cad9fce1097174a7aa268a27deca42d895ee83b6745364e3a821f2686820490a1726c262274a4aa2d158ff1bd87d5ed61b88323feac00efb03b85eaf4ef30c38035943d7f89ac5f8050553483e8d5f2f6c4e44ad7fa77835c328edc71e11d8bed56a9e5de36a28a20a590ed415f62a8bdbafe3b3f81e6c568ce3d609c1408b9df97ce41bfc6e10fc58126c1048ad7ee9dba557931075e2942d36b9c83f8b14c57a1ec4fa13b78347501825a72749165651892509cfe49518f54a89717c68e8bef7cf9155fdaed6416baee524b19621138070c672b1dc2a7cf61dadda688d24e2f562eb22161752f2ad8ec645a84c1a494690b2ab883dc595ee5ee732f90ce10015bc32ad3240c9cbe81d27b1a51b395c35664d39d3949ef937c63a28543fefaa999cc91fabccb9bf6013dff4633a9db05390e170ddcaa9b471fecfea785aedc663bf06522193b98f4b9267c5148370d63b4f4e381cb523bd47e6da56bb3738fb689c2f4d38e1153943e9ec9a0a3ef15196c7b277e3cda01bcfec4bcea2150fbf23f893b0fa0447372f66ab34a1160d7e7b841046e348f98699e712
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86476);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2014-6450");
  script_bugtraq_id(77125);
  script_xref(name:"JSA", value:"JSA10699");

  script_name(english:"Juniper Junos IPv6 Packet Handling mbuf Chain Corruption DoS (JSA10699)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to a
flaw related to the processing of IPv6 packets. An unauthenticated,
remote attacker can exploit this, via a specially crafted IPv6 packet,
to trigger an 'mbuf' chain corruption, resulting in a kernel panic and
a denial of service condition.

Note that this issue only affects devices with IPv6 enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10699");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10699.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['11.4'   ] = '11.4R12-S4';  # or 11.4R13
fixes['12.1X44'] = '12.1X44-D41';
fixes['12.1X46'] = '12.1X46-D26';
fixes['12.1X47'] = '12.1X47-D11'; # or 12.1X47-D15
fixes['12.2'   ] = '12.2R9';
fixes['12.2X50'] = '12.2X50-D70';
fixes['12.3'   ] = '12.3R8';
fixes['12.3X48'] = '12.3X48-D10';
fixes['12.3X50'] = '12.3X50-D42';
fixes['13.1'   ] = '13.1R4-S3';   # or 13.1R5
fixes['13.1X49'] = '13.1X49-D42';
fixes['13.1X50'] = '13.1X50-D30';
fixes['13.2'   ] = '13.2R6';
fixes['13.2X51'] = '13.2X51-D26';
fixes['13.2X52'] = '13.2X52-D15';
fixes['13.3'   ] = '13.3R3-S3';   # or 13.1R4
fixes['14.1'   ] = '14.1R3';
fixes['14.2'   ] = '14.2R1';
fixes['15.1'   ] = '15.1R1';
fixes['15.1X49'] = '15.1X49-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if(fix == '11.4R12-S4')
  fix += ' or 11.4R13';
if(fix == '12.1X47-D11')
  fix += ' or 12.1X47-D15';
if(fix == '13.1R4-S3')
  fix += ' or 13.1R5';
if(fix == '13.3R3-S3')
  fix += 'or 13.1R4';

# Check if IPv6 is enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set interfaces .* family inet6 ";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because no interfaces have IPv6 enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
