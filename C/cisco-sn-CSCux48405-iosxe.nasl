#TRUSTED 9d71b7ec335063ebdfdd0e73e4b6e6302bd4ff91ba033d9e4b049a10a92727fae09483ba48b2f4139461116b982cad9632d21b5e159262a7210c56f88af6e9a6a5ff470b225e23c6af79607d13ca0fc2c7b73b2cacb3db32c52d435dc86aa5678efd06665e0c54303ddce57aff4e53e724f1df60b8af584ad7dfe2c895ab1c47a2c10df2c913d7ab2220a404dbf3c9421cc0f4c38b4a791d1eb510657433b1cab88d13e908b05a4ba9e0a7a4cf3f5521bf796b333ab4b9ad7318282a11fed727f630868af012e30d6eeb05eb5f4095b738b4d4a554df5af700d5f9a3ff779b6141589cdee84fc91425d7ab2b0cc26863fc5fe90c9071efe85d0621806e63406a1ea5fdd7c9bc3386599f691e2fff5c7aff0b44399c80b377f91906a858dd5d577af95ef4055f737b0520e9ad535a4b16334d706a4516ca5773ec9d18e4634303cfacc1eb5289257bddd19d28d471b6563b18d52339e74128e226a2e174a1dadaec41c5daefc0f1bcd214d23466fe792c195266b06dedec09ac2e55f3f7e4948dd7cfcbba673138f58100dfbc45f0c5be963cccb95ef56a1950ab9a5db73f60e4ccf1965b72681edf5598eae408f27d49f0518ebb875fe3983c55e97e9e2cc6bae8e2b82244fd95536e4b01fecd0277bdaa84620f09ac87c1db7595a2582b5a79c57508f59fddc7babec083e6addce2028413b4bac5cc3a77738095acd137d058
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87847);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-6431");
  script_bugtraq_id(79654);
  script_xref(name:"CISCO-BUG-ID", value:"CSCux48405");
  script_xref(name:"CISCO-SA", value:"cisco-sa-2015-1221-iosxe");

  script_name(english:"Cisco IOS XE Source MAC Address DoS (CSCux48405)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is Release 16.1.1. It is, therefore,
affected by a denial of service vulnerability due to incorrect
processing of packets that have 0000:0000:0000 as a source MAC
address. An unauthenticated, adjacent attacker can exploit this to
cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-2015-1221-iosxe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38f90004");
  script_set_attribute(attribute:"see_also", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCux48405");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-6431");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;

# Check for the single vulnerable version
# 16.1.1
if (
  ver =~ "^16\.1\.1$"
)
{
  flag++;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux48405' +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report );
    exit(0);
  }
  else security_warning(port:0);
}
else audit(AUDIT_HOST_NOT, "affected");
