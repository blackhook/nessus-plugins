#TRUSTED 9bbd936f410a00611dba0f87d3c3e4d9993d28d591c83d0942e5f2eb8f385400bc93a10c6545693708999b80b783b0b7e1c350a10f7400e046b5d34539cbef5c732fc99b142bbe5968cfe7cfe49ac87ece1b9ecfe5b138284b3e9347f9bf868764fcfe41b9ecd8c0db00bc294276edfd0f56de436071dbc6c43edb6d151fe7900f5be7f58fae0f4287c5de47ec6b04a1128c6b906062812fbe4b6978924af968d2853bf03184c2b7fcc512b0527e15ab079e48749a11b6c9c09568619bc657caf3a5f4a3a49be3c467eb3f80494d52331268319aa21d6eed250aecabaaf1c51e94ad24e610e15ce9efce105cfe7bf702009baa89684e42fbf3346ac31521ffd91e72ddec8e3ea57955d76294947550d683525ffd19fa0bb0342878522685e165e299aee6335f9e2153882bf244973bb1f2adf73be8313f6515aecb5b690cb3c7fbf491cb68b006770d2dccd5585f8b770b8737106ba822d106105a08c5a342bd865afe8300ff3cca0b917228a48b6295460e74db60b473cf6f5020d1c05eea6f21514da0c8e8b0d2f3473c18809008c97f686cbd8ad20c38f26a2c7798d354b454e59c56be048c6e9da786ae3b2929c0abfc173cc5354a345f4328e7211587fee82144a18d8ae5d018865bfe50c4d1fa5367aa1bf4098b4ff38acdeea383edf09aa5b40f7668596bdd1ba5f7c823b08aee4f95b909011aae47be2181d310302f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93122);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2016-1459");
  script_bugtraq_id(91800);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz21061");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160715-bgp");

  script_name(english:"Cisco IOS Software Border Gateway Protocol Message Processing DoS (cisco-sa-20160715-bgp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS Software running on the remote device is missing a
security patch. It is, therefore, affected by a denial of service
vulnerability in the Border Gateway Protocol (BGP) message processing
functions due to improper processing of BGP attributes. An
authenticated, remote attacker can exploit this, via specially crafted
BGP messages under certain unspecified conditions, to cause the
affected device to reload.

Note that Nessus has not tested for the presence of the workarounds
referenced in the vendor advisory.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160715-bgp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94ed1c7e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20160715-bgp. Alternatively, set a 'maxpath-limit' value for
BGP MIBs or suppress the use of BGP MIBs.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1459");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

app_name = "Cisco IOS";
version  = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (
  version != "Cisco IOS 12.4(19a)" &&
  version != "Cisco IOS 12.4(24)GC4" &&
  version != "Cisco IOS 12.4(24)GC5" &&
  version != "Cisco IOS 12.4(15)T17" &&
  version != "Cisco IOS 12.4(4)XC7" &&
  version != "Cisco IOS 12.4(22)YB2" &&
  version != "Cisco IOS 15.0(1)EX" &&
  version != "Cisco IOS 15.0(1)M" &&
  version != "Cisco IOS 15.0(1)M10" &&
  version != "Cisco IOS 15.0(1)M9" &&
  version != "Cisco IOS 15.0(1)S" &&
  version != "Cisco IOS 15.0(2)SG" &&
  version != "Cisco IOS 15.0(1)SY" &&
  version != "Cisco IOS 15.1(4)GC2" &&
  version != "Cisco IOS 15.1(4)M10" &&
  version != "Cisco IOS 15.1(3)T4" &&
  version != "Cisco IOS 15.2(4)GC3" &&
  version != "Cisco IOS 15.2(4)M10" &&
  version != "Cisco IOS 15.2(3)T4" &&
  version != "Cisco IOS 15.3(3)M" &&
  version != "Cisco IOS 15.3(3)M7" &&
  version != "Cisco IOS 15.3(2)T4" &&
  version != "Cisco IOS 15.4(3)M5" &&
  version != "Cisco IOS 15.4(2)T4" &&
  version != "Cisco IOS 15.5(3)M3" &&
  version != "Cisco IOS 15.5(2)T3"
)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

# We don't check for workarounds, so only flag if paranoid
if (report_paranoia < 2) audit(AUDIT_PARANOID);

## If the target does not have BGP active, exit

caveat = '';

# Since cisco_ios_version.nasl removes "Host/local_checks_enabled" when report_paranoia > 1,
# we will try to run the command without checking for local checks; a failure will return NULL
buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_bgp", "show ip bgp", 0);

# check_cisco_result() would cause false positives on devices that do not support BGP,
# so we are only looking for authorization-related error messages or NULL
if ( ("% This command is not authorized" >< buf) || ("ERROR: Command authorization failed" >< buf) || empty_or_null(buf) )
    caveat = cisco_caveat();
else if (!preg(pattern:"BGP table version", multiline:TRUE, string:buf))
    audit(AUDIT_HOST_NOT, "affected because BGP is not active");

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCuz21061' +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : ' + report_fixed_version +
    '\n';
  security_warning(port:0, extra:report + caveat);
}
else security_warning(port:0, extra:caveat);
