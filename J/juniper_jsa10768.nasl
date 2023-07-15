#TRUSTED 20bddaf33c8435497508eb55f50594657ea9f0d608e265798df9e6db0048fbf389e0a7ea4e3e81857a75ffb2be0e0e483a8027472350c1a460a076f1e7e340d45e27db49021fab5a35054ad6ad7fd33aaf6c09d234317e299c80999b4af02e87c49abce6dbe34690665386c94ffff47b32acf4ceabdb86215fe556d80e368268a5eb9c74abf1a166da7bf9724c7aa2c7667ba6de3e70e074d030d7fd194c1d6cc51c733ac7ee75de2b15678e498750afc2e5d6afecf6d9fecaa541830635607837397540f4165531a296c8573868012934c41a29010972656ff12ae797c8873a429e0cf5211bebed0a8e0cd21d2de7b83ffb0c2dc6340ac704cb719032aa3d0fe84f1ce36ccd05109405ce9b1d12afa2ee8473a7fa1d87a4bdd497d79cee8e307851b47d24d3b314bb44319fbe01803f323906e7676b50478b16d974f4fa6fb26720e3128d86a0257e82eebe5485fca27fdc6f19ca31fc5f8d39bfa9be3f903bbeeab07bf9822c90de926d8b2f75267b87c4c7d469de76fb6bc3cf9667608c9a9467b45ca2a6cbdfda44e149f79c2d7ae58b9fcb5f67e9c22fef81d9f9ef70ca30affcbcc98743c0d51c4dafb8388da0f4f5d831fee2babd9cbed0344156572106d676889491e8d85a9e59a152699b7279ff914aeb2efa374fe0bb3e2431d164cec552fac2a9ac7a4e5c4a07f1c04e6859c0681a1048f7ba8d4aa3e98429cece
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96658);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2300");
  script_bugtraq_id(95400);
  script_xref(name:"JSA", value:"JSA10768");

  script_name(english:"Juniper Junos SRX Series Gateway Chassis Cluster flowd Multicast Session DoS (JSA10768)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos SRX series device is affected by a denial of
service vulnerability in the flow daemon (flowd) when handling
multicast session synchronization. An unauthenticated, adjacent
attacker can exploit this issue, by sending specially crafted
multicast packets, to cause the flowd daemon to crash and restart.

Note that this vulnerability only occurs in chassis cluster
configurations that process transit multicast traffic. Transit
multicast traffic is processed on an SRX services gateway by enabling
PIM in normal Flow Mode, or via security policies permitting transit
multicast traffic in L2/Transparent Mode.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version, model, and current configuration.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10768");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10768.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

fixes = make_array();
fixes['12.1X46'] = '12.1X46-D65';
fixes['12.3X48'] = '12.3X48-D40';
fixes['15.1X49'] = '15.1X49-D60';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Check if PIM is disabled globally or family or per-interface
  # Global
  if (preg(string:buf, pattern:"^set protocols pim disable$", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'affected because PIM is disabled globally');

  lines = split(buf, sep:'\n', keep:FALSE);

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
    nics  = make_list();

    #  Grab NICs with PIM activated
    foreach line (lines)
    {
      pattern = "^set protocols pim interface (\S+)";
    
      if (junos_check_config(buf:buf, pattern:pattern))
      {
        matches = pregmatch(string:line, pattern:pattern);
        if (matches)
          nics = make_list(nics, matches[1]);
      }
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
  if (override) audit(AUDIT_HOST_NOT, 'affected because PIM is not enabled on any interfaces');
}
  
buf = junos_command_kb_item(cmd:"show chassis cluster statistics");
if (buf)
{
  if (preg(string:buf, pattern:"Chassis cluster is not enabled", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because the chassis cluster is not enabled");
  else
    override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
