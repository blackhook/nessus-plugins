#TRUSTED 7cadf10b0f43f936773b27461cec0cdf2930f08530976139fc87101635abaf75c367ad9469c280054b4c5bda57da04ec21d45aa19b279929e39e951171ac61c0df00dc4ed82d357a53502ed70e2d419ae5cfefa55144437d1834af08707b34984a620adba61adf3b565909e6ba129a93afd94c652ca6a6892ba02439b0e5c048f879acbf62075b38bcc287619614c317b2de655b724eaffa26f3096cab2e998a01398173ec2c1b23dd9d4ed0c6c87482c445bf97c35e3bedf27cade5feaacaa58483fd7ccd4d984cdebbcf45b48a59bfb631368d6d86a137f3bb0b6806540e6e721c02e5bfce2cf7a80c50457db1410012994ee9a9533147ea03de51de61b66b262a093313bc60db6779b6ac2fd11e33e5d7532af129b4d3f7c26e4b5149150f9c5511a8297ac0ea4658b39018f7119dffd821c09add8322ca7462bc7336d802f653b89d31a3b911fa4756d16a56d412a0634b72474762ab91d655a927e11842d0b23609ad1d536cbedc857940a348b7f94d1b98083b7f0968f265199fb0a8aa7ac93cf08a3f4caef8663763f035aa66e05d4ad3d3b8e3664c35b09fe3e99ffd61e45c7c7150e215dcd680a20f2df2da8125c611e35c93eea52d28e90529e0d63d97af656ce0130f4aa49cb179240153a4240d8b013f1fee9739a87afdba9e725f29a94a6d399ef4d9727d8fedb23f63f170a95a1e5e78a191e4380e939448ff
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92518);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/12/09");

  script_cve_id("CVE-2016-1275");
  script_bugtraq_id(91758);
  script_xref(name:"JSA", value:"JSA10750");

  script_name(english:"Juniper Junos VPLS Ethernet Frame MAC Address Remote DoS (JSA10750)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a denial of service
vulnerability when VPLS routing-instances are configured. An
unauthenticated, adjacent attacker can exploit this, via Ethernet
frames with the EtherType field of IPv6 (0x86DD), to cause a denial of
service condition.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10750");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10750. Alternatively, if EtherType IPv6 MAC addresses are
not required, configure a VPLS flood filter.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1275");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['13.3'] = '13.3R9';
fixes['14.1'] = '14.1R6-S1'; # or 14.1R7
fixes['14.2'] = '14.2R1';
fixes['15.1R'] = '15.1R1';
fixes['15.1F'] = '15.1F2';
fixes['16.1R'] = '16.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "14.1R6-S1")
  fix += " or 14.1R7";

override = TRUE;
buf = junos_command_kb_item(cmd:"show route instance detail");
if (buf)
{
  pattern = "Type:\s+vpls\s+State:\s+Active";
  if (!pgrep(string:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because no VPLS routing-instances are configured');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
