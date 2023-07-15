#TRUSTED 3d3b5236dbc7aa600045638a0dcc3c7ee3b80df527bdc375886d1195247a142d58b3cd5987cb4bda80c6174ca8508c0d34e1af27346a61d20cf77b14d04fbd44d8e82e0a9a963d5704215d8e0f6d4dfc974d86a0675fbb4d3e7956cf604d3162b5f30a89eac43f275f7635e6c1da0360db49dddf7af62790d7bc635ee932c8b4c78bee7624f83bfce7c2fdce27b747713e645922b98e248c62e60f2dd59a46efa7f3662ffe2aee1f521e985a56a3418a3f77a72484e9bbbeaed6728e5c85c919935588ec2eb97adc2ff637bd59cb9114110813f0044ff09be9998ba1a3d240e83592d4256d9f448e21a73815b47e31f8ce8ebd82569c67fdb431258085d3beee2ead0b677b43b23a38aa3af7a227be020454a3b24888044ed14b252a950c85caaf6b6892d27f9fdfa86a6f0c1afbb45ae1292054cb975cb4a3801a23c149aac26a756e2f52b93097644be35a0a4ccce035dce33c2a3e6f85a67fed2d140ffc5149d1f5bffcee655d99cad067a748b786fc08f91d44287aa962e3ee0442e55ecae0a5a0c5eb384cb060d24be8ff06fc3b9678e0347370a38c51369b86ebf037146e1caf28514367dd8bcf43ce61fa6b974f160efa86d58ced2842c28bd1474ca853838305098e9f631cceadbba945d1d5afac94fc7e2707d2cc9c58e95ccf1642447a845031e32d27b1e4c379852a5e9a7558896ee2738a0982c458446fcdb826
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78691);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2013-6706");
  script_bugtraq_id(63979);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj23992");

  script_name(english:"Cisco IOS XE IP Header Sanity Check DoS (CSCuj23992)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS XE device is
affected by a denial of service vulnerability in the Cisco Express
Forwarding processing module.

The issue is due to improper processing of MPLS packets. When certain
additional features are configured, an attacker can exploit this
vulnerability by sending MPLS packets to traverse and exit an affected
device as IP packets. This may cause the device to reload.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31950");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31950
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4249565d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuj23992.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6706");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# this advisory only addresses CISCO ASR 1000 series
model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");
if (model !~ '^ASR 10[0-9][0-9]($|[^0-9])') audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
override = 0;

if (version == '3.9.0S') flag++;
else if (version == '3.9.1S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (
        preg(multiline:TRUE, pattern:"ip cef accounting", string:buf) && 
        preg(multiline:TRUE, pattern:"tcp adjust-mss", string:buf)
      ) flag = 1;
    }
    else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuj23992' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
