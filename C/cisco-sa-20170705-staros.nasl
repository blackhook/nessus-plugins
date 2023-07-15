#TRUSTED 37af5cb108d2d4bcc27bca1fd821245612668fe4d950c0dcdf4f7206c6e6d2894c02623c7420d20682912288ac34dc25a40e32f97e8f8b3135879ea97bd5d85e35ab57e2d53f7aacd8d91a068300170b1f3d644ab3a35cad43cd4a52a68412c30196fe5360cf7a89321af27af5a915df820b02ed221c92d30cf6d2c02385b2bbb6799aefb282ee4be21b859ad94023e012badcde1fa82620f6f5f29098ee64bad816dde4cd4e430b8f37dc0f488ebdb5af88d611facca75af99774cded5aaf969260d88ce0199db7db64b5303a5d369dfc7f68fd8f50f01b3af41941ab10c78225effd6bc379ccf13582b49426b6436231f9fb62a687e9f1ad6eae63b9c470e37f3c89c2e61510628abf6f9464e9078a4e2a54355155a8cb933d1c5ca2d5902407776fde43eedcec08125590ef64e2e9b74797a33cc3469d8ab2a09098e9877ec39491253394c77c1240c71c28d3f04f1571d277938ac4d490566ae62b29f0502afa41d0021798d44dd6b7135ffb2bb40f85d0a4693f5e094a569528ae7b933c49ce79ee9a24409d0684caf3027127d0bda0614252000e42949db690cc63e14da5cced1e53101259ee48ee987ce0a0acdb0ee4009c9b6571f11d74ac6a4dd7519f60150a8773b8c1d2415748cf4e228e222b56880dd05affe28d3928bb2794ac15c5c303e8f545401dc3cbbf7d4859c485708fa405c42b9ef3f3ed73fba9cc91
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101529);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-6729");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc44968");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170705-staros");

  script_name(english:"Cisco ASR StarOS Border Gateway Protocol Process DoS (cisco-sa-20170705-staros)");
  script_summary(english:"Checks the StarOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and model number, the remote
Cisco ASR device is affected by a denial of service vulnerability in
StarOS in the Border Gateway Protocol (BGP) processing functionality
due to improper boundary controls for the peering sessions list. An
unauthenticated, remote attacker can exploit this, via specially
crafted TCP packets, to cause the BGP process to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170705-staros
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0decdaed");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc44968");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvc44968.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6729");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:staros");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asr_5000");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:asr_5000_series_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASR/Model", "Host/Cisco/StarOS");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

get_kb_item_or_exit("Host/Cisco/StarOS");

version  = get_kb_item_or_exit("Host/Cisco/StarOS/Version");
model   = get_kb_item_or_exit("Host/Cisco/ASR/Model");

major = NULL;
build = NULL;
fix = NULL;
train = NULL;
flag = NULL;

# only affects ASR 5000/5500/5700 series systems
if (model !~ "^50\d{2}$")
  audit(AUDIT_DEVICE_NOT_VULN, 'The ASR ' + model);

# Normalize train characters
version= toupper(version);

# For newer versions, We may be able to get the build number during detection
build = get_kb_item("Host/Cisco/StarOS/Build");
if (!empty_or_null(build))
  version += "." + build;

# defensive check for the pregmatches below
if (version !~ "^[\d\.]+\([\d\.]+" &&
    version !~ "^[\d\.]+([A-Z]{1,2}\d+)?\.\d+$")
  audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);

# old style of versioning 15.0(5439), style change mid 16.1, making
# all of the old style versions fall into the vulnerable range.
if ("(" >< version)
{
  major = pregmatch(pattern:"^([\d\.]+)\(", string:version);

  if(!isnull(major))
  {
    major = major[1];

    if (isnull(build))
    {
      build = pregmatch(pattern:"^[\d\.]+\(([\d\.]+)", string:version);
      if(!isnull(build))
      {
        build = build[1];

        # Set the train to an empty string, or it causes issues when
        # seeing if a patched version exists using NULL as the value
        train = '';
      }
      else
        exit(1, "Unable to extract build number.");
    }
  }
  else
    exit(1, "Unable to extract version number.");
}
else
{
  # extract major, train, and build for new style
  extract = pregmatch(pattern:"^([\d\.]+)\.([A-Z]{1,2}\d+)?\.?(\d+)?", string:version);
  if (!isnull(extract))
  {
    major = extract[1];
    train = extract[2];
    if (isnull(build))
      build = extract[3];
  }
}

# Defensive checking for versions that we haven't yet seen
if(empty_or_null(major) || empty_or_null(build))
  exit(1, "An error occurred during version extraction.");

fix_array = make_array(
  "19.7", make_array( "M0", 67570 ),
  "21.1", make_array( "M0", 65894, "R0", 65898,
                      "V0", 66014, "b0", 66164 ),
  "21.2", make_array( "A0", 65905 )
);

# CVRF states that 16.4.1 is the first vulnerable
if (ver_compare(ver:major, minver:"16.4.1", fix:"19.6.6", strict:FALSE) < 0)
  fix = "19.6.7.67568";
else if (ver_compare(ver:major, minver:"20.0", fix:"21.0", strict:FALSE) < 0)
  fix = "21.1.0.66030";

if (major == "19.6.7" && int(build) < 67568)
  fix = "19.6.7.67568";
else if (major == "21.1.0" && int(build) < 66030)
  fix = "21.1.0.66030";

else if (
          !empty_or_null(fix_array[major]) &&
          !empty_or_null(train) &&
          int(build) < fix_array[major][train]
        )
  fix = major + "." + train + "." + string(fix_array[major][train]);

if(!isnull(fix)) flag = TRUE;
else audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);

if(flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if ('router bgp' >< buf) flag = TRUE;
  } else if (cisco_needs_enable(buf)) { flag = TRUE; override = TRUE; }
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    fix      : fix,
    bug_id   : 'CSCvc44968',
    cmds     : make_list('show running-config')
  );
}
else audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);
