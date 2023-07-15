#TRUSTED 216d71255f09d0718cefd9639207bba566647e2389d255274073c53fd4e966df19011ad2783807ff910222fef45b929edb72e321c61caf1f1b57b71f3692828b90089aa04820e15f88cd733bef1d2bfc5e44e549e4754c16ca1900046cb27028ac092f716b89ae185d3872a8284ff981bd64ee5d6bc071611fb0f67f9529181bbbd300bd9464c5fe20b1411713704074b2b8397cdb8f55a176b76ecc6d4f7105f9adc1f274fc4eeb43821ed3600bc1e0bab97046de247274af49b5bd52b9feb636d8101aef0cb67f3b46e3595eaacb138e00f1652499976dfd9240d6a390f68116fd410d64d1198e48cad4c9be77348e094e16ee24960bde887f2834dba3b55a30501c2e2bfc6f3d4ff9c92fe7d32c564fc0c0724921c07a7d8568766ee0c17fe88dff73ad27d7455a6627bee507b7e6826a7eec24b810f1e133f655c16f075c0f72425419d388fa186c6fbcbbd55f52f015c77937dccf7a966d5ba79a540ae3e3cd9145589762e7d05294ffc02d30ecf594e91867daf05225f16af72312bfdb12611e423f5389fa74c904e4bace23df002a4979d587e0b3e7d6b55d0ba65c03fde30fd0d5bbe21f7f6232e599e5ac25c8a92d970b62d2df782d6df1156d8f06b07078e391618cec8248fb0e440b357807a497f8b09ba87c39e774998e87a985563ee1308842c016072271812a1dab99aa16187abbbb8e01d2be35ded02ae878
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90359);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-1349");
  script_xref(name:"TRA", value:"TRA-2016-04");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv45410");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-smi");

  script_name(english:"Cisco IOS XE Smart Install Packet Image List Parameter Handling DoS (cisco-sa-20160323-smi)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Smart Install client feature due to improper
handling of image list parameters. An unauthenticated, remote attacker
can exploit this issue, via crafted Smart Install packets, to cause
the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-smi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14b003f9");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-04");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuv45410. Alternatively, disable the Smart Install feature per the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1349");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/06");

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
override = 0;

# Check for vuln version
if ( ver == '3.2.0JA' ) flag++;
if ( ver == '3.2.0SE' ) flag++;
if ( ver == '3.2.1SE' ) flag++;
if ( ver == '3.2.2SE' ) flag++;
if ( ver == '3.2.3SE' ) flag++;
if ( ver == '3.3.0SE' ) flag++;
if ( ver == '3.3.1SE' ) flag++;
if ( ver == '3.3.2SE' ) flag++;
if ( ver == '3.3.3SE' ) flag++;
if ( ver == '3.3.4SE' ) flag++;
if ( ver == '3.3.5SE' ) flag++;
if ( ver == '3.3.0XO' ) flag++;
if ( ver == '3.3.1XO' ) flag++;
if ( ver == '3.3.2XO' ) flag++;
if ( ver == '3.4.0SG' ) flag++;
if ( ver == '3.4.1SG' ) flag++;
if ( ver == '3.4.2SG' ) flag++;
if ( ver == '3.4.3SG' ) flag++;
if ( ver == '3.4.4SG' ) flag++;
if ( ver == '3.4.5SG' ) flag++;
if ( ver == '3.4.6SG' ) flag++;
if ( ver == '3.5.0E' ) flag++;
if ( ver == '3.5.1E' ) flag++;
if ( ver == '3.5.2E' ) flag++;
if ( ver == '3.5.3E' ) flag++;
if ( ver == '3.6.0E' ) flag++;
if ( ver == '3.6.1E' ) flag++;
if ( ver == '3.6.2aE' ) flag++;
if ( ver == '3.6.2E' ) flag++;
if ( ver == '3.7.0E' ) flag++;
if ( ver == '3.7.1E' ) flag++;
if ( ver == '3.7.2E' ) flag++;

# Check for Smart Install client feature
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
  if (check_cisco_result(buf))
  {
    if ( (preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient", string:buf)) &&
         (!preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient\s+\(SmartInstall disabled\)", string:buf)) ) { flag = 1; }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuv45410' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
