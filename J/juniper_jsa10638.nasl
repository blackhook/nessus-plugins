#TRUSTED 5f434e6a7c9071c098304ae4af638cae9e07441ec814ff789ba27e107cac76abef7c2374ec35060d25ffc87ef9d8179e7e01382d569dcf61c9c4cbb7908ddcbf5bb8bfabf7ceeb43e2c7cc13e07f1541545264e1323e7c24403c913f87c8a8fa98fe3e2d2168757d58f92281f787eb33ed9330375e20cdb71e6ed1bfd278c425d2ce70a592ad637d623cd65ffc9f5286b589434a2188f6f03adab1503b7c264b83ed546f887d21411714e8df0b010e90ff22982a594abf65c3bbb93e95344879398005ba48331e1cd09626761f4de83e8d4d8c93f0d8e30b5682e750c9f2898df0132c161dcad7fe433e5067c0841596a1d6cea0e0b19ae753e1a5ec8f3a8c5614de3875b8dae96ec6776c1ff7da29f83868d6944327cf15be132f8cfa716526ffc847ac2922845c66ec908f666481e3db0d4cbdffa65fc3e557bffe5e1d4c469b69ab1a0d934cf913bd6f014420c048c6c43b09308e91ac5dfa2b9776f737f11a7e978d03eb8b4ad196f015498b9cd72e0bc74571cf700ed48d882f991132d40abe5a98e0e3dedbeb22a330acb68f443d3c7574c205a620c36f2e7a648ec094b2ef308f03ca2215583621f46422558776559f782880213e4fbf9983ce6a02b3d8f7b047c2ccfd7fb6e303806a1be67ace3413cfa44cc3bd06e108a5929134f5efd8f3c985e1968066464e6409117953e39f93ab4b9522a269257d6820ffc435
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76506);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/07/12");

  script_cve_id("CVE-2004-0230");
  script_bugtraq_id(10183);
  script_xref(name:"JSA", value:"JSA10638");

  script_name(english:"Juniper Junos TCP Packet Processing Remote DoS (JSA10638)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability. An
attacker who can guess an in-window sequence number, source and
destination addresses, and port numbers can exploit this vulnerability
to reset any established TCP session.

This issue only affects TCP sessions terminating on the router.
Transit traffic and TCP Proxy services are unaffected by this
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10638");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10638.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/15");

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

ver        = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

# Junos OS 14.1R1 release date
if (compare_build_dates(build_date, '2014-06-26') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['11.4']    = '11.4R11';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.1']    = '12.1R10';
fixes['12.2']    = '12.2R8';
fixes['12.3']    = '12.3R6';
fixes['13.1']    = '13.1R4';
fixes['13.2']    = '13.2R4';
fixes['13.3']    = '13.3R2';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
# Multiple workarounds are available but all other workarounds are difficult to check
if (buf)
{
  pattern = "^set system internet-options tcp-reset-syn-acknowledge";
  if (junos_check_config(buf:buf, pattern:pattern))
    override = FALSE;
  # Display caveat instead of checking for other workarounds/auditing out
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
