#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(108520);
  script_version("1.7");
  script_cvs_date("Date: 2019/06/11 15:17:50");

  script_cve_id(
    "CVE-2015-5174",
    "CVE-2015-5188",
    "CVE-2015-5220",
    "CVE-2015-5304",
    "CVE-2015-7236",
    "CVE-2015-7501",
    "CVE-2016-2141",
    "CVE-2016-8743",
    "CVE-2017-1000111",
    "CVE-2017-1000112",
    "CVE-2017-12172",
    "CVE-2017-14106",
    "CVE-2017-15098",
    "CVE-2017-3167",
    "CVE-2017-3169",
    "CVE-2017-5645",
    "CVE-2017-5664",
    "CVE-2017-7668",
    "CVE-2017-7679",
    "CVE-2017-9788",
    "CVE-2017-9798",
    "CVE-2018-0011",
    "CVE-2018-0012",
    "CVE-2018-0013"
  );
  script_bugtraq_id(
    57974,
    76771,
    77345,
    78215,
    79788,
    83329,
    91481,
    95077,
    97702,
    98888,
    99134,
    99135,
    99137,
    99170,
    99569,
    100262,
    100267,
    100872,
    100878,
    101781,
    101949
  );

  script_name(english:"Juniper Junos Space < 17.2R1 Multiple Vulnerabilities (JSA10838)");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 17.2R1. It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10838");
  script_set_attribute(attribute:"solution", value:"Upgrade to Junos Space 17.2R1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'17.2R1', severity:SECURITY_HOLE);
