#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104036);
  script_version("1.5");
  script_cvs_date("Date: 2018/07/13 15:08:46");

  script_cve_id("CVE-2017-10613");
  script_xref(name:"JSA", value:"JSA10816");

  script_name(english:"Juniper Junos Kernel Vulnerability (JSA10816)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a vulnerability in the loopback interface that could
cause the kernel to hang.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10816&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?496f4c5d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workarounds referenced in
Juniper advisory JSA10816.");
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


# Affected:
# 12.1X46 prior to 12.1X46-D55
# 12.3X48 prior to 12.3X48-D35
# 14.1 prior to 14.1R8-S4 or 14.1R9
# 14.1X53 prior to 14.1X53-D40
# 14.2 prior to 14.2R4-S9 or 14.2R7-S8 or 14.2R8
# 15.1 prior to 15.1F5-S3 or 15.1F6
# 15.1R4
# 15.1X49 prior to 15.1X49-D60
# 15.1X53 prior to 15.1X53-D47
# 16.1 prior to 16.1R2
fixes = make_array();
fixes['12.1X46']     = '12.1X46-D55';
fixes['12.3X48']     = '12.3X48-D35';
fixes['14.1']        = '14.1R8-S4';
fixes['14.1X53']     = '14.1X53-D40';
fixes['15.1F']       = '15.1F5-S3';
fixes['15.1R']       = '15.1R4';
fixes['15.1X49']     = '15.1X49-D60';
fixes['15.1X53']     = '15.1X53-D47';
fixes['16.1']        = '16.1R2';
fixes['16.2']        = '16.2R1';

if (ver =~ "^14\.2R[0-4]")  fixes['14.2'] = '14.2R4-S9';
else if (ver =~ "^14\.2R[5-7]") fixes['14.2'] = '14.2R7-S8';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
