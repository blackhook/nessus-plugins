#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104032);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id("CVE-2017-10607");
  script_xref(name:"JSA", value:"JSA10810");

  script_name(english:"Juniper Junos BGP PDU Vulnerability (JSA10810)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a vulnerability in the way the router receives a crafted BGP PDU.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10810&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09c9d843");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10810.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

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

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

# 16.1 prior to 16.1R2
# 16.2 prior to 16.2R1
fixes = make_array();
fixes['16.1']    = '16.1R2';
fixes['16.2']    = '16.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
