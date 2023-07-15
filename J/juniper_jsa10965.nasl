#TRUSTED a90c5dc84682cfe7a1ba34c046990caf5fe98c156aa40a45ea457656c1f937fbd2c7a629171684d03c79a933a1863ff1e622b2782eaa8a61b04dd3e1e3ff01cd7620f8577fe36894fa98da968df1b07b6fd8f2379efe35845bddba0fa29b1659ad2fbb16466363007d8583900755a47044814fa6d9b4f21349ab9e5baf4eda996933db80e7f9b54877b0a3b74bc0469cfef6f181e4ace4dd117f9960ad34e15888a7b8f6a02206ac067b01cd852439a97bd3fd81cb1803b08941ebaa572e2b497759c410be0b82f1740e678192741a8e46c0aeb89ccfbf831f2cfd415398ac03f733cfd7f33d4ba1493dea939b9f7f338363680b5222dd20d0c473372203a046675632206b33fa900b4293eb95a7ffe195abc0d910849bf17521a17c6452619c16ee5ba4f9796d59c0ffecf5ad3d3ea34208fb033496a15e1ee42d81fa3dab49e75e8e91ede54836a2388bd81d13b7178a6372e7785a26db85ef437d052d79a6ded41eab1febadd5740bec9de4ec27c3f0d8292b76c45eb767aa8f8524caf3fbccd1bf0f17f3c0ccf0a0f5086127e4d049c5d4d6cd388b4dd7d29ad1dc0a6d6c8f3370cd2f1a46e7bb511b6daa0766f2c9f0cdf03eed7a686bdfdd93036c96a523d9192a4d27a40fc9e427d262389732cf2b80f3227fc174ffee9c272a8c882e449c8b840cbbf9bb0230f98322da58ba7d7109ce165b1ae040759793e9a50cf5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130504);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0066");
  script_xref(name:"JSA", value:"JSA10965");
  script_xref(name:"IAVA", value:"2019-A-0388");

  script_name(english:"Junos OS: NG-mVPN rpd DoS (JSA10965)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper Junos device is affected by an unexpected status
return value weakness in the Next-Generation Multicast VPN (NG-mVPN) which can result in a denial of service (DoS)
condition. An unauthenticated, remote attacker can exploit this issue, by repeatedly sending crafted, malformed IPv4
packets to a victim device, including when these packets are forwarded directly through a device, provided that the
malformed packet is not first de-encapsulated from an encapsulated format by a receiving device. This allows an
attacker to cause the system to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10965");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10965.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0066");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

fixes = make_array();

fixes['15.1R'] = '15.1R7-S2';
fixes['15.1F'] = '15.1F6-S12';
fixes['16.2'] = '16.2R2-S7';
fixes['17.1'] = '17.1R2-S9';
fixes['17.3'] = '17.3R2-S4';

# 15.1X49 versions prior to 15.1X49-D150 on SRX Series;
if ('SRX' >< model)
  fixes['15.1X49'] = '15.1X49-D150';

# Advisory says: 15.1X53 versions prior to 15.1X53-D68, 15.1X53-D235, 15.1X53-D495, 15.1X53-D590;
# Making this check paranoid ?
if (report_paranoia >= 2)
  fixes['15.1X53'] = '15.1X53-D68';

# 16.1 versions prior to 16.1R3-S10, 16.1R4-S12, 16.1R6-S6, 16.1R7-S2;
if (ver =~ "^16\.1R4($|[^0-9])") fixes['16.1R'] = '16.1R4-S12';
else if (ver =~ "^16\.1R6($|[^0-9])") fixes['16.1R'] = '16.1R6-S6';
else if (ver =~ "^16\.1R7($|[^0-9])") fixes['16.1R'] = '16.1R7-S2';
else fixes['16.1R'] = '16.1R3-S10';

# 17.2 versions prior to 17.2R1-S7, 17.2R2-S6, 17.2R3;
if (ver =~ "^17\.2R1($|[^0-9])")        fixes['17.2R'] = '17.2R1-S7';
else fixes['17.2R'] = '17.2R2-S6';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If BGP is not enabled, audit out.
# Same as juniper_jsa10799.nasl
override = TRUE;
buf = junos_command_kb_item(cmd:'show bgp neighbor');
if (buf)
{
  override = FALSE;
  if (preg(string:buf, pattern:"BGP.* instance is not running", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because BGP is not enabled");
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
