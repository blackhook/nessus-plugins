#TRUSTED 856e94b594e5dbcc989040607f0c1a1a2e65e67432f71e4fddfbe0aeeec6cd40924a9f667a24030b3a40c87f3175a77cb6c1a47bd2ebcafa3a6f5a201e98304f2352dbce2efbc6e48a849da954273ad3fc4414d4e9e5c6e5f77677c7e4e57eba4e5491bac78b5541215687f287187833b0186b8f19b505044feacac4158b86c19d1512c4646eb60268fe100804cf38d0acd4b2bc1bb380b58ea42bcb6724f8d7e6bbb4a46b2de4a5be7c8e7e2fa9f6df56a6249e8a4359788ad6d2bee52a049d1d8e4e751ac68bf29fc4d28c804dd0e958761b49aa5adaf1937bf8209d6aa930912a565377ea8b8cb2b5ae38eb3d25a6452e3035f8ca6849c73254802194533a8f128d0db6350d9e7c851ff803d1e8480aaa5a0371de16cc3273bf57786df7e40b5b420e83c321272c86eb4e4ce594f3a3a12641363aebd648dac1aa5e26b5ebc0f6ac651b082ec335bfc5af50a6761044bcac2e521bf0e9b29e5edd3854d39dd3fdb255a25ddc6c9d5761d879894a4fc16c11aa1521b948e24a07ea4924aa1f72adbe37eb5e695a6eb38f495d5b0c2453f0cb766a6235dd600b122528e23df9d3d96807ed1b5b32c84cd6462791f1ef10a18c0d4279c56882b86b5ae0f2e806c97b01a765aa7589a66850e292d4d58c942cd40020dd26e9284afaf596ef5911a3144affc7159f9f6e1d44ada156400e445ecbf256c0a3b0873573abcb9e47b5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85227);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2015-5359");
  script_bugtraq_id(75723);
  script_xref(name:"JSA", value:"JSA10687");

  script_name(english:"Juniper Junos BGP-VPLS Advertisements RPD DoS (JSA10687)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to
improper handling of BGP-VPLS advertisements with updated BGP local
preference values. A remote attacker can exploit this to crash RDP
with a NULL pointer deference exception.

Note that this issue only affects devices with internal BGP and VPLS
enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10687");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10687.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");

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
fixes['12.1X44'] = '12.1X44-D50';
fixes['12.1X46'] = '12.1X46-D35';
fixes['12.1X47'] = '12.1X47-D25';
fixes['12.3']    = '12.3R9';
fixes['12.3X48'] = '12.3X48-D10';
fixes['13.2']    = '13.2R7';
fixes['13.3']    = '13.3R5';
fixes['14.1']    = '14.1R3-S2';
fixes['14.2']    = '14.2R2';
fixes['15.1']    = '15.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

#IBGP and VPLS must be configured
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Internal BGP (IBGP)
  pattern = "^set protocols bgp group \S+ type internal";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because internal BGP is not enabled');
  
  # Check that BGP-VPLS is configured
  buf = junos_command_kb_item(cmd:"show vpls connections");
  if (buf) 
  {
    pattern = "^BGP-VPLS State$";
    if (preg(string:buf, pattern:pattern, icase:TRUE, multiline:TRUE))
      audit(AUDIT_HOST_NOT, 'affected because no interfaces have IPv6 enabled');
  }

  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
