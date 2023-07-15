#TRUSTED 045192cb5774f4ef75b6ee28df46a885a1a2d525d9edd60d83641aafabd622b32c0c66d7028272375b0b70a2997fc7047f81dc26ec4b97f8fad096371d893df587b50b62cf4a43ef421adcaaeddc24128dbfa745b09dad52260688dac803f512b801e79470e8ba1c3966358ee2f5442db8ba17e3d045895010f6cd6c45674503ca65f91f6016a819b9d760dfa97b343be47d12db570fd3746000b721dd6194518ec031c06307a1fdf22d7560542ad82e0e00e56ad9e48227e326d519700806b35607452e39cb579bf8a6428d5307822fe9cf06d5fbf4a1a47668324ec6cebf2d51ab675ba767e2dd92377da3d43031490d6dc1285052d1d8df6f35c75149e5f0be687494fadc159abfab54bcbe53fee70ffe7b882bc1987de5624b29ede345baa18bb435f562c85e47a4ed417db6d7a1c3992eda57525f68679162bc64fe4f60d100db101e696738e85031e176cfcf2e31ad707dc02840b036f3cd329b3b8db5cb16f06eca0f7d3683c76c994f4678c72345f3a7f0cbeb3a22db16f5a7e4e0676bcfeb3872c00142bdc8a02073e30dbfdc14447e7bd6d3ec424bcf1f6f77591778b7d4a7b64844f737decadf2680a777591f0bb5d2b62ea770c32dc2a11934f9204145a28e7985d3246a3cb43fcfda1c8208a68e4a594576dafce9040eff7d83afa0611b2567c38f0e88339fba1af32dd0b1a5b8e0942edc6b124ee3a245d7ab
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82587);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0641");
  script_bugtraq_id(73337);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub68073");

  script_name(english:"Cisco IOS XE IPv6 DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability due to improper parsing of IPv6
packets. An unauthenticated, remote attacker, using crafted IPv6
packets, can exploit this to cause a device reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cbb5bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCub68073");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# CVRF
if (version == "3.1.0S") flag++;
if (version == "3.1.1S") flag++;
if (version == "3.1.2S") flag++;
if (version == "3.1.3S") flag++;
if (version == "3.1.4S") flag++;
if (version == "3.1.5S") flag++;
if (version == "3.1.6S") flag++;
if (version == "3.2.0S") flag++;
if (version == "3.2.1S") flag++;
if (version == "3.2.2S") flag++;
if (version == "3.2.3S") flag++;
if (version == "3.3.0S") flag++;
if (version == "3.3.1S") flag++;
if (version == "3.3.2S") flag++;
if (version == "3.4.0S") flag++;
if (version == "3.4.1S") flag++;
if (version == "3.4.2S") flag++;
if (version == "3.4.3S") flag++;
if (version == "3.4.4S") flag++;
if (version == "3.4.5S") flag++;
if (version == "3.4.6S") flag++;
if (version == "3.5.0S") flag++;
if (version == "3.5.1S") flag++;
if (version == "3.5.2S") flag++;
if (version == "3.6.0S") flag++;
if (version == "3.6.1S") flag++;
if (version == "3.6.2S") flag++;
if (version == "3.7.0S") flag++;
if (version == "3.7.1S") flag++;
if (version == "3.7.2S") flag++;
if (version == "3.7.3S") flag++;
if (version == "3.7.4S") flag++;
if (version == "3.7.5S") flag++;
if (version == "3.7.6S") flag++;
if (version == "3.7.7S") flag++;
if (version == "3.8.0S") flag++;
if (version == "3.8.1S") flag++;
if (version == "3.8.2S") flag++;

# From SA (and not covered by Bug or CVRF)
if (version =~ "^2\.") flag++;

# Check NAT config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^ipv6 address ", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^ipv6 enable ", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCub68073' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
