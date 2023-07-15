#TRUSTED ad72fb1737b6dbec40f1ccf933fc5c70c118a79c6cc3a4c091b6fe0c885a9326f95f619034a7cacaf8cff50df183e78b091877627e1a73f3a4dfa19049d76572ab99e618869b03ef2942c3af645136c42239bbef333ba134d84005d3d203320899e1d3fa03964bc2c85ca907ce0124146c042962d4264a1bbb9b22913a3389903577dbd51d96ed6422a653cfb2bc4733899db3c5d44ef37fe9ca508a1ab84178be9de4c47a3df614886d659041392b8044daded71772793260248d1b68b34b2cd55633b2a6a680f3339026f156a7478e503910d84b516aa85fa7aec6bd7e9f62fe67a12cdd8847c2f85cdd46ba4579928ec645528bc038512a5dd89dfd382ba8b3832131370316aa23477a43f26d02879210f1dee5cc8eaffb5ec0572a5f99b9b8a12b4d4d728866314f586dbf8ab0568759587b2512bd3717770ccb4a279ea779fd889b1bc987b76a34aabf7d2e4607dc191f21c427f93e87ff86f40632680c01bf4dc63bd29067156119739ae9089dd25abdb51d44e1d45d6062936064a40fa8cedea570fdb9167d1821587e7c82e87990abea13b29c6fdf5e80bbb788581ec830bdc037b1202d88c4fdf1587d28dcc8d17a2d6798d359c887ee6679f4d631bb761d48eb2983e6ee359bfa0038b8b7276d448d5276009ad1c6bffb4d3ae19bdbb455d67903c91d4def0a93ae033dc6d1fc4d334a73a35c16e84de3c2d81722
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70480);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2013-6014");
  script_bugtraq_id(63391);
  script_xref(name:"JSA", value:"JSA10595");

  script_name(english:"Juniper Junos Unnumbered Interface Cache Poisoning Remote DoS and Information Disclosure (JSA10595)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by denial of service and information
disclosure vulnerabilities. An adjacent attacker can poison the ARP
cache and create a bogus forwarding table entry for an IP address,
effectively creating a denial of service for that subscriber or
interface or leading to information disclosure as the router answers
any ARP message from any IP address.

Note that these issues only affect devices that have Proxy ARP enabled
on an unnumbered interface.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10595");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10595.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

if (compare_build_dates(build_date, '2013-09-18') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4S15';
fixes['11.4'] = '11.4R9';
fixes['11.4X27'] = '11.4X27.44';
fixes['12.1'] = '12.1R7';
fixes['12.1X44'] = '12.1X44-D20';
fixes['12.1X45'] = '12.1X45-D15';
fixes['12.2'] = '12.2R6';
fixes['12.3'] = '12.3R3';
fixes['13.1'] = '13.1R3';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check if PIM is disabled globally or family or per-interface
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  # Grab NICs w/ Proxy ARP activated
  lines = split(buf, sep:'\n', keep:FALSE);
  nics  = make_list();

  foreach line (lines)
  {
    pattern = "^set (?:logical-systems \S+ )?interfaces (\S+) unit \S+ proxy-arp ";
    # Check if the NICs w/ Proxy ARP are disabled or deactivated
    if (junos_check_config(buf:buf, pattern:pattern))
    {
      matches = pregmatch(string:line, pattern:pattern);
      if (matches)
        nics = make_list(nics, matches[1]);
    }
  }
  # Check if any interface is 'unnumbered' (essentially not assigned an IP)
  foreach nic (list_uniq(nics))
  {
    pattern = "^set interfaces " + nic + " .* address ";
    if (!junos_check_config(buf:buf, pattern:pattern))
    {
      override = FALSE;
      break;
    }
  }

  if (override) audit(AUDIT_HOST_NOT,
    'affected because Proxy ARP is not enabled on an unnumbered interface');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
