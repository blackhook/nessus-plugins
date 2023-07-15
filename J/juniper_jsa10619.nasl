#TRUSTED 30f76fa9cc7d6992ee6d0db1553c3e40500a147168692b50c3bd1ad4b3f3009ad98792d5857e202ff31f3a49bf2c7e006e69927c3d883cc4436f4321d15fd65fe977fa0b717128bacee7e1039de1e224e806211451c7e1e0fc078adc98e7e5d9d5a1e101714d324aad3cf7bbfc371a00fe0bfb52d23766548a2fa32ab9c7123086c1e38a4f0c50811497854e8c6f3792e3e035eebad050a54d7ab92e209e71375c14b595f8ad808c983de9e7001650f83e27d6270c3b1d5a403cdb7977481f7decdc01a4cbe543555f6c42836dc506714ab80549245d0ed6bb4e4dfde09f4bf13f6b7f63abbd1648cccb467e86a9f143d29bb951a4c5ee433025dca054b9cf4c98b3a598a0e91ec2de7945819872a8c4ee1ddbfa571c56306366b252a6e2cf70de52c8795a80ccdf85976916504e14e86817af7996406fa3d55d0680f8a9c3f0eec4c46e6c537168898d3b8e38832464b855063f85cad092fc09d1c3d7d03cc446f33b833d4310a6a7bdb64a72c60c789c89fe7236d67bbaafabc5d390df6b4478441cb99853f654b495bc6e4a2eea8356e10d3088e80edfd7a3103b43443bdb2fa058749c5753ab0f19acbc963fc6910213d5eae183749f1075c6297ff2c14bb83008de98789fafabeb5cc5150a45ab215e6f9d49742dcf6de8ab124c2ae7ef92cb5d9b952f1f57918317782b0dbc5b5603c5d522fe7e986c1b1110f2839244
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73493);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-2711");
  script_bugtraq_id(66770);
  script_xref(name:"JSA", value:"JSA10619");

  script_name(english:"Juniper Junos J-Web Persistent XSS (JSA10619)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a stored cross-site scripting vulnerability due to a
failure to sanitize user-supplied input to the J-Web interface. An
attacker can exploit this vulnerability to execute arbitrary
JavaScript in the context of the end-user's browser.

Note that this issue only affects devices with J-Web enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10619");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10619.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2014-03-20') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['11.4X27'] = '11.4X27.62';
fixes['12.1']    = '12.1R9';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.2']    = '12.2R7';
fixes['12.3']    = '12.3R6';
fixes['13.1']    = '13.1R4';
fixes['13.2']    = '13.2R3';
fixes['13.3']    = '13.3R1';

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

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING, xss:TRUE);
