#TRUSTED 9025b126558d170469e608a4bcc46c486afdcc5dcf98568476e8c4a8c0c903110e328f84086457c33b40ad3f9cee6652c713f3ec91e0af8be17be41fb251795194646b8a8e4a4e337b20003452ab26ebba1aa49a608c9b985a8f92080636398bbdf535a0450e0b30dcfb78a19e65e4828c08c7f2e7e4d2315d1ae05b695161bdb8b05f6d2cc4a7ee1d5e523d8cb13b09044c3cd7620aa05c3675cf79dced641c3a845e8f43c95cd3ffe7e20ddc7a6272198a189c251ef0bbb8a4fac241d0d4f2e8dd9a9faf33ff604f158026a7e71110ff1c376aa7f5421d64a64c8fd4922665fe7e63e1e1dab175da24c430a9c35012ad7401ef1b930f6a29dd4a68241729ab96d10dd4e4a04b38ab7cae48d433f830cb08cef83fcc5cde5554af28e4e2cc81f93c07a9ef03d69e400516fd9f11a847e013023430510771bfea094998eaaa98339a793a257a26a95fdb397d7805ccb9c48b781e9ce8b196b8e731e51cd87c212dfdf12b5be9ce1dd175b1705064463c7293ab7fe8efd2db002041600a768fe4d300eeec7193cb0a335ac8bb837850099106abb271aada0978f6b6566d228b34c22c88c0ef2549fec98d8a66ba38f7704b5952e593c3745b6c9bd0be1f3c302f93295aa28162645da80129f061af739e7e6a112ee87b76bca3b7a4fdb971f1c418466bef05b6947e8690cb966ec1e8c06118291d1b0db9376545e1f3b595119f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87504);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-6359");
  script_bugtraq_id(79200);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup28217");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151214-ios");

  script_name(english:"Cisco IOS XE Software IPv6 Neighbor Discovery DoS (CSCup28217)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch, and is not configured to limit the IPv6 neighbor discovery (ND)
cache. It is, therefore, affected by a denial of service vulnerability
due to insufficient bounds on internal tables. An unauthenticated,
adjacent attacker can exploit this, via a continuous stream of ND
messages, to exhaust available memory resources, resulting in a denial
of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151214-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dba1bec0");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup28217");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup28217.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if ( "ASR" >!< model ) audit(AUDIT_HOST_NOT, "affected");

flag     = 0;
override = FALSE;

if (
  version =~ '^[0-2]\\.' ||
  version =~ '^3\\.([0-9]|1[0-4])\\.' ||
  version =~ '^3\\.15\\.[01]($|[^0-9])' ||
  version =~ '^3\\.16\\.0($|[^0-9])'
) flag = 1;
else audit(AUDIT_HOST_NOT, "affected");

if (flag && get_kb_item("Host/local_checks_enabled") && (report_paranoia < 2))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ("ipv6 nd cache interface-limit" >!< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (flag || override)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup28217' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report+cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
} else audit(AUDIT_HOST_NOT, "affected");
