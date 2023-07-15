#TRUSTED 54a6c96579044a7ab0d9873135112f9a217b4cb0ec09e67f0aa06c75f48e168b6ec1e9c71d31c2e73c94c9e6355ec3aac09f2c8c85232b19f3573f16556e120ab30f11ff12085a3d523a021573692ebc8e3d5648b9b7c91ef7d44761ad2b02395a4d95e885298061958ad6869fd74c3c445b26ee2363bf4627969a3675f5f57e1214b354fc5f1d6566292cedfc627250bda813e428d6abc3c4c5d41708cda97fdf849f5e8acf14af9b4d63925ff357687ea5ab75215f2507e2a039baf99ca7453bb865625ebac8f32e96cf3ce06f821b6a3afe2775277eb7ecb58d96e6d1d54e896bff05189922ee46772501637664cd82be92fbfd3f2b7085aba5a27e26e6e601bcd73c9b5ee3593a6dc80aaef7be8130671d955defcf95506eacb4858bbeb6e7ffa96443dd1eb66d30c784982073e066476471f2a391331c9d350b6b1236837a078aaf69d4eac35124ba62c70a2ecf87e3efd662655e325ac46e6fb8e47051a92aaf3d1c6b6af65e062cfd08f7577d6a6f133926d61d7f437969df87da24709bfed60bc0c3118e6fef9b0069edf093cfbfa69597f074893d08538701895cdc007d5a60bec104409367a58210816fd2ba4bd1c4c56e8e6eb83803f13fafb02cde274f9c99e0aec37e4ccf7454b0808a350155ca58edfec112ac1c1eab55f504cdc6ec4bdd0667fca935cd15bb1f55dce22fcad0f78056f61b65cba98b76c847
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93123);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2016-1459");
  script_bugtraq_id(91800);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz21061");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160715-bgp");

  script_name(english:"Cisco IOS XE Software Border Gateway Protocol Message Processing DoS (cisco-sa-20160715-bgp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE Software running on the remote device is missing a
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

app_name = "Cisco IOS-XE";
version  = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

if (
  version != "Cisco IOS XE Software 3.13S 3.13.5S" &&
  version != "Cisco IOS XE Software 3.13S 3.13.2S" &&
  version != "Cisco IOS XE Software 3.13S 3.13.3S" &&
  version != "Cisco IOS XE Software 3.13S 3.13.4S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.0S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.1S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.2S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.3S" &&
  version != "Cisco IOS XE Software 3.14S 3.14.4S" &&
  version != "Cisco IOS XE Software 3.15S 3.15.1cS" &&
  version != "Cisco IOS XE Software 3.15S 3.15.3S" &&
  version != "Cisco IOS XE Software 3.15S 3.15.2S" &&
  version != "Cisco IOS XE Software 3.17S 3.17.0S" &&
  version != "Cisco IOS XE Software 3.17S 3.17.2S" &&
  version != "Cisco IOS XE Software 3.17S 3.17.1S" &&
  version != "Cisco IOS XE Software 3.16S 3.16.3S" &&
  version != "Cisco IOS XE Software 3.16S 3.16.0cS" &&
  version != "Cisco IOS XE Software 3.16S 3.16.1aS" &&
  version != "Cisco IOS XE Software 3.16S 3.16.2S"
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
