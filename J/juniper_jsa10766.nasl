#TRUSTED 069386568d28bd2cd8c0bcbb10dc882d76ffb00897b0065f44a924bb8d1df16341435da212f5560f7e31a38d267107ba35edaf744c2e9be6067783d2164b0304aebc7f73bafca72e19089c964c9afc0a8dc760088adbddbf1071c17a2fcafdbd038a5f93a9ab17c5a86d4cea1c48b2ee81adef021814c1684b3bf5dc08507431d83f4ae254cb927801f902f5ae33b12311e101a66c54ae17d97f5864b20d8fdd348ed878a636ffef86c02e55500a287214b9305ccd7c41709408ffa79a0f1541a71e4e8160663959676c33ed4bd3ec8432f103751da2678b1bb87cc1a88de2af435d76d92f11cd299c475a852c812ba98abf284356e17f60b48ded955ccac43697632795832132e7e7dfeb79f7ae3433954829359532fd2a41f6add855c7180836e6d89c814675d6822ec0a12a6d03a07ac425a8eb0d4e4532b775787d5e617b3dfa7d19554633400ba5f9570164a20a20a23c053c0c399470a2069f992c68404e47b88ba90e8c140e94eba9d16fe7e15e7e8a33af01285666b4ae3b7e93e61e7ab10d9158a12be8c6cae8409b0093b1c666c2f7ff798d03612959827e7a8c3a34bd6c0deb82ca73fcba4de95d5da8348ce0a7ae2ae0adf646e57649e3c10f4d4ce79f4617813f3b6d0ed821fdc5ea4ee5a781634402bc83b7fd6a0270f99fdc9ad679a63569aba7ae9b9fe15b3e45eb6f1525a2f63d6b0b1c5f14158d47ba26
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94579);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2016-4924");
  script_bugtraq_id(93531);
  script_xref(name:"JSA", value:"JSA10766");
  script_xref(name:"IAVA", value:"2016-A-0295");

  script_name(english:"Juniper Junos vMX 14.1 < 14.1R8 / 15.1 < 15.1F5 Local Information Disclosure (JSA10766)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and architecture, the
remote Juniper Junos vMX (Virtual MX Series) router is 14.1 prior to
14.1R8 or 15.1 prior to 15.1F5. It is, therefore, affected by a local
information disclosure vulnerability due to the use of incorrect
permissions. A local attacker can exploit this to disclose sensitive
information in vMX or vPFE images, including private cryptographic
keys.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10766");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper Junos vMX 14.1R8 / 15.1F5 as referenced in Juniper
advisory JSA10766.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:vmx");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
if(model != "VMX") audit(AUDIT_HOST_NOT, "a Juniper vMX device");

if(ver !~ "^1[45]\.1") audit(AUDIT_INST_VER_NOT_VULN, "Junos", ver);

match = ereg_replace(string:ver, pattern:'^(([0-9]+\\.[0-9]+)(?:([A-Z])([0-9]+))?(\\.([0-9]+))?)(?:-[0-9.]+)?$', replace:"\1");
if(!empty_or_null(match)) ver = match;

fixes = make_array();
fixes['14.1'] = '14.1R8';
fixes['15.1F'] = '15.1F5';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_WARNING);
