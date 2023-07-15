#TRUSTED 8797b565f79314c0abb0fc98380446da034483ce01f90e859eaf23360e80e5b367fb4de13df36cbb8f3b79c72c7f10e39a680c5c6f5f44305b6dca5deb5134d44162d92dc288a03eb64d069453147d01f30f3ee54105d286d4ee67289a5675e94dcabd34533baf9695ff654c5b69939d1c058f5b713317ecea79aa933c3890e992fcd47e143878f392da8368f05094e6ef1441ea77d44e146a0de3ad5cbd4791d7084a6acb651d89fba19e945fea6332396cd56df0d6fd5ea8a5f84536ed29c58b28b4893a137bc75fcf5eafce9c1dec31129e7b08d558cd4d3e9d461e3691c7c643d68be7efaa2ee49c95413c31549d27e62c031c051190018a579ed1b8e7ea6ef726ecb5d515dcdf614c174474b8c9530ed6b6fadce7c2ccf71add2f3f8d1e87e6e542155f73ebfddf8e8dbc5c649139d0d36e8d022752d131c6c922732bff15ea146bf64eeadba2671fb5a9252add0780f347c2a3595a962baa487e4ed5faa4619cd5875a702e69bd01329fc54acc7e04b3e30bddc6c59a9e44bd8f0dca397d57b3447e2104bba49fb0f2c259e09a1e134bffd235673eeaa883b8ecc59f2c58a16076b950b58476a5faeb64d96dd592a84de8f430a4bd4523db46c5cb087765cec872c871ef98ae17720636f3ae3e68dd4b44f850a7eda99d78e80e6080019fcc93a379cda27d28e36e58cfcf5caae731dd54c1c8375d6d35b6dfa21d69da
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78690);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2013-6706");
  script_bugtraq_id(63979);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj23992");

  script_name(english:"Cisco IOS IP Header Sanity Check DoS (CSCuj23992)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS device is
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# this advisory only addresses CISCO ASR 1000 series
model = get_kb_item_or_exit("Host/Cisco/IOS/Model");
if (model !~ '^ASR 10[0-9][0-9]($|[^0-9])') audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
override = 0;

if (version == '15.3(2)S1') flag++;
else if (version == '15.3(2)S') flag++;
else if (version == '15.0(1)S') flag++;

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
