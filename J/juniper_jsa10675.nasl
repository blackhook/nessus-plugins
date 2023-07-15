#TRUSTED 74542addc5d8ba369f890783fffc1ca372a9a6c38de94fe2fa58a93e16f32c21862fff384ecaeb65b6bd8e5d9356abe869982db81e790ed189065a03bba5f62f04894fca6c3628e5ea4ea427cacd873e98795a6659f41ef2bd0251743564d2bf7f6d8a648642527b806426a20172604f20e50497a06670942bb0188ad98624667631bd2f1d6634004729a317d12855b2dd9d877e241ebdae432b3b19d58d2105a82ac3e835e5ea9360903f7a39f65e69ee32cfcce91dacc6ddc285d55f152d21a3e414ef4fa0f60857caed43f86eaccb737a0bb791259da2fdffbc1358cb59dc5583d7cc6c49599581a24d8b87105ad6d35d248802332f1b890b3ba0a785c32a765289180c18f306baab878b788b2370ef82c550cc63de273c463920ff764c06c69fb0fb76e43771649f5b0cfc9a5a754a075e3539212f8a59220e5c862b33f173c17456a6499e323300269eb7e45d22fe451482b24b8a32081497f099575a6243f88eccae4622f5c1651f9def55ee5b2aa3b8d9211a468b7d6eec18b2b0257add42303c537d55bac677fdc7cba30d2c6434bee7637e5303f9410f22c99af1960b4d6a77d97873a7ed102ed8415831ad2b8a3264ce3cac270af661c13decbfb6a8d1b5711eb30943bb4a33635be2b96611002babb3b88315a0afb61669db6cc18c8ba0217adfe67292ab496e598d4c686fd4e39b01501cc297304fefa0770189
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82796);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2015-3004");
  script_bugtraq_id(74017);
  script_xref(name:"JSA", value:"JSA10675");

  script_name(english:"Juniper Junos X-Frame-Options Clickjacking (JSA10675)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a clickjacking vulnerability due to J-Web
missing the 'X-Frame-Options' HTTP header. A remote attacker can
exploit this to trick a user into executing administrative tasks.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10675");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10675.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/15");

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
fixes['11.4'] = '11.4R12';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X46'] = '12.1X46-D25';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2'] = '12.2R9';
fixes['12.3'] = '12.3R7';
fixes['12.3X48'] = '12.3X48-D10';
fixes['13.2'] = '13.2R6';
fixes['13.2X51'] = '13.2X51-D20';
fixes['13.3'] = '13.3R5';
fixes['14.1'] = '14.1R3';
fixes['14.1X53'] = '14.1X53-D10';
fixes['14.2'] = '14.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for J-Web
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management http(s)? interface";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because J-Web is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
