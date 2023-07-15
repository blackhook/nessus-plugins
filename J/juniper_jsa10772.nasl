#TRUSTED a10185afec06f0103d38b749b2a4e99e58ada58e5a27535f6bb9bdf8aebf014ef910df3c4993d2dcdda6a2c14b8d4324eaf09a87c375579f2ec9e956419e668bc3de609c3a7e4f5769dbe0f04ec9b10b0c7659769c055c7094c4f89e38afdd7b7650e86a8a429e08e83fdfe8419d405882c03eb260b01fcb4c194e6f330c1dfd969c97ec19f89294af57f6ff6e450c9823d12c17896ba73a8849aef7a6581bdcf14c7cebf935caacfbc2696e8586f5efbfa882a8c2e72fa341126bed52bbbf6bf53fbe1c7492beb5699c7b87a1793c1d396502e8be281f32786b8ab00369c8cb29b2b397b5eaca4baaf9d08a6c112c629540dd9c60fb3427e7ce02c9235aa9dbca7b7625863b4bafac85c740d8df6357a77d41a4045baaa96c3868d2de9c0e613ce9bc0c45372a4c3182db8d7d338827b8ab09a180876d323d218020eae0ff43ed680e392f8b6f2302f1165cbf5ef7db681b4284ad5bff0724b74cd0510497e391737e4f437e9dc6d1524853474aea75bb855570984307aa26ca03aa7ea5c638cbb805da8144acf79c0808a60711e42e37350d212ba1f7b49fc8566f36a4753cc11679f2bf397ad0bf8e2920bccba24f919194ed148bc1f075aa3d24254aefb8f8533ef6b3a8e81088622803946769ee9ca0bded3b201b878b768ad96a9de013b93c2e35c34fc30870d0c75b77364671b8211aa65a65adcfd1e1ff8970b657ef
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96661);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2303");
  script_bugtraq_id(95408);
  script_xref(name:"JSA", value:"JSA10772");

  script_name(english:"Juniper Junos rpd RIP DoS (JSA10772)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability in the routing process daemon (rpd) due to improper
handling of RIP advertisements. An unauthenticated, remote attacker
can exploit this issue, by sending a specially crafted RIP
advertisement, to cause the rpd daemon to crash and restart.

Note that this vulnerability only affects devices that are configured
with RIP enabled.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and current configuration.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10772");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10772.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['12.1X46'] = '12.1X46-D50';
fixes['12.1X47'] = '12.1X47-D40';
fixes['12.3']    = '12.3R13';
fixes['12.3X48'] = '12.3X48-D30';
fixes['13.2X51'] = '13.2X51-D40';
fixes['13.3']    = '13.3R10';
fixes['14.1']    = '14.1R8';
fixes['14.1X53'] = '14.1X53-D35';
fixes['14.1X55'] = '14.1X55-D35';
fixes['14.2']    = '14.2R5';
fixes['15.1F']   = '15.1F6';
fixes['15.1R']   = '15.1R3';
fixes['15.1X49'] = '15.1X49-D30'; # or 15.1X49-D40
fixes['15.1X53'] = '15.1X53-D35';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show rip neighbor");
if (buf)
{
  if (preg(string:buf, pattern:"RIP.* instance is not running", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because RIP is not enabled"); 
  else
    override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
