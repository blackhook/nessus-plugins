#TRUSTED 0518004f472da6c594707f8202e799c6049bdcec6425ab0dda3b5d97322354008ad484f827f2a4b8ddd1cf7456d5aea0057b2350b681178dda44c97da334814b18576748efdec6a27d1ff6044f76c5bbf5677c35ebc41dbeafb878bc426b635c9e5f4170c4ff9bc0a7d0507fd5cc5796617c932ec3ffcef96f2a3d21060feaef9307bea58656015814b271012419f15f0675e5100bfabdcf46ccb23265f33bee5ea10fa69b47e2772ef88b28542989b2bebcb2d7c61cce4c193199e69aaa4808fb6ee6fda94001d0f1268135c05918704eb3625e5da991bbb5d996c1425b55924a2e43714283d1fd460d4c9beb50868872a0e530f1eec625a9ab8a58409d3ea9a1bc1a12568d1a28f48e4c2a66cb6c43787ca48a125da702d79b70f6f7903a40d09dca69958f6ee20b8c516a8f288e58140a7d0b8ec131e9dc58271aaf5ca486f44c0f69193e00c4dd7434dbfa1797b08db06c6f595ead8687201e209085110bb2a046ef5e6155df03f194155c39f730caae51e2a94cd37bc8ca260b60ec3494e151889bdffd4edb0200837d75be1b65cfca75ba9a2b330ca528e056928c5d010e5ed77a903455206aae2f9253dfcbf0fae2daf9fae9c8684d7caebd9ecd0d70c6aeffd5b77bc56d2b2e43a2d9e034609691c883f69ecfd912d64b9aae7ed054f66f5dcb39772eccd9cd9bb1659498de82ebcd7be5502587e0f41c0a84abc687
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88990);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22654");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140605-openssl");

  script_name(english:"Cisco IOS XR OpenSSL Security Bypass (CSCup22654)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of IOS XR software that
is affected by security bypass vulnerability in the bundled OpenSSL
library due to an unspecified error that can allow an attacker to
cause the usage of weak keying material, leading to simplified
man-in-the-middle attacks.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aa6a7e6");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup22654");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup22654.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
override = FALSE;

# all releases from 4.3.1 through 5.2.0 are affected
if (
  !(
    version =~ "^4\.3\.[1-9]" ||
    version =~ "^5\.[01]\."   ||
    version =~ "^5\.2\.0($|[^0-9])"
  )
) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (!isnull(get_kb_item("Host/local_checks_enabled")))
{
  flag = FALSE;
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_all", "show running-config all");

  # Check for services utilizing SSL/TLS
  if (check_cisco_result(buf))
  {
    override = FALSE;

    if (
      # Web UI HTTPS
      preg(string:buf, pattern:"^http server ssl", multiline:TRUE) ||
      # XML Agent
      cisco_check_sections(
        config:buf,
        section_regex:"^xml agent ssl",
        config_regex:'^\\s*no shutdown'
      )
    ) flag++;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = TRUE;
    override = TRUE;
  }

  if (!flag)
    audit(AUDIT_HOST_NOT, "affected because it does not appear as though any service utilizing the OpenSSL library is enabled");

}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : CSCup22654' +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : 5.3.0' +
    '\n';
  security_warning(port:port, extra:report+cisco_caveat(override));
}
else security_warning(port:port, extra:cisco_caveat(override));
