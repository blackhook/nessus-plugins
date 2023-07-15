#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104038);
  script_version("1.6");
  script_cvs_date("Date: 2018/07/13 15:08:46");

  script_cve_id("CVE-2017-10615");
  script_xref(name:"JSA", value:"JSA10817");

  script_name(english:"Juniper Junos Remote Execution Vulnerability (JSA10818)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a vulnerability in the pluggable authentication module 
(PAM) of Juniper Networks Junos OS that may allow an unauthenticated network 
based attacker to potentially execute arbitrary code or crash daemons 
such as telnetd or sshd that make use of PAM.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10818&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb27d038");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10818.");
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

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

# Affected:
# 14.1 from 14.1R5 prior to 14.1R8-S4 or 14.1R9;
# 14.1X53 prior to 14.1X53-D50 on EX and QFX series;
# 14.2 from 14.2R3 prior to 14.2R7-S8 or 14.2R8;
fixes = make_array();
fixes['14.1']  = '14.1R8-S4';
fixes['14.2']  = '14.2R7-S8';

if (model =~ '^EX[0-9]'|| model =~ '^QFX[0-9]')
  fixes['14.1X53']     = '14.1X53-D46';


fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
