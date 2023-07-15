#TRUSTED a068a70d8b00762407a91eca71dc2afb6f9f5c78e89706de797a26828b47e4b7463f61bb54d66a96e5d5193ed5c71521cf951af9b0abde19db1b25f8669ca02cef80bf2a223942910f10aa83d969f5c72e2cbcc17826315d34f546362b8c57ca9b76ad3bea22eaffd88499497dbbc4e6fdd76cf17a59fe044f4ae76ffae8612b4b3557f517bd776e9d56af2041ae2ae31739e431c6ca4053164396eab9fc35d7694d10353a296c50b460803da83999f9f63b061af12ebd80bd5e08d3f33f3879957b7a797d1a756f35b9199fde065d0ced480a4edd234ca40e4317fb09568e8a8ac8912c3478491c6c2637b648d01ebb99f08c9ac51aa135704db68b0e4954454ea675c8e00dd5ac06469198c16336fcc33b20143aeae503f7b4369c40184542eb203d628715673c9c20e16e980e28cabce288c7cdc87dc4a1004b13bb69b33cfff08c48d66e5ad1aa59f7ef90623e9a9e9cf37bde95539d7386956b9f7cd7662c6334a1873aa7c740198f411816cfb24450c49a0ff2ac20436689396a6de89faa92548c74dc15b00c3d9bccca2444b8e6f22f40d072b2db1486ec008154d7ed3e8ea9e4ced38331570d9128ec03b353184c3126850fbbe39714c9a85c20a9d73d1b15390d9b05cf111dea7b0396139687f49361e1ed025f907ebbc7b3477f0416a9469b4c1527683d64751a69fdbd4acec6988dc4e66ff43ae5618450547f68
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73492);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2014-0614");
  script_bugtraq_id(66762);
  script_xref(name:"JSA", value:"JSA10618");

  script_name(english:"Juniper Junos Kernel IGMP Flood DoS (JSA10618)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by denial of service vulnerability in the
Junos kernel. A remote attacker can exploit this issue by sending
specially crafted IGMP packets at a very high rate (approximately 1000
packets per second). 

Note that this issue only affects devices with PIM enabled."); 
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10618");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10618.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/16");
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

if (compare_build_dates(build_date, '2014-01-16') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['13.2'] = '13.2R3';
fixes['13.3'] = '13.3R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if PIM is disabled globally or family or per-interface
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Global
  if (preg(string:buf, pattern:"^set protocols pim disable$", multiline:TRUE))
    audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

  # Families
  patterns = make_list(
    "^set protocols pim family inet(\s|$)",
    "^set protocols pim family inet6",
    "^set protocols pim rp local family inet(\s|$)",
    "^set protocols pim rp local family inet6"
  );

  foreach pattern (patterns)
  {
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    }
  }

  # Per-interface
  if (override)
  {
    lines = split(buf, sep:'\n', keep:FALSE);
    nics  = make_list();

    #  Grab NICs with PIM activated
    foreach line (lines)
    {
      pattern = "^set protocols pim interface (\S+)";
      matches = pregmatch(string:line, pattern:pattern);
      if (matches)
        nics = make_list(nics, matches[1]);
    }

    #  Check if any of the NICs have PIM enabled
    foreach nic (list_uniq(nics))
    {
      pattern = "^set protocols pim interface " + nic;
      if (junos_check_config(buf:buf, pattern:pattern))
      {
        override = FALSE;
        break;
      }
    }
  }

  if (override) audit(AUDIT_HOST_NOT, 'affected because PIM is not enabled');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
