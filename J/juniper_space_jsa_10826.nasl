#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(104100);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
    "CVE-2017-10612",
    "CVE-2017-10623",
    "CVE-2017-10624",
    "CVE-2017-7494",
    "CVE-2017-1000365",
    "CVE-2017-1000366",
    "CVE-2017-1000371",
    "CVE-2017-1000379",
    "CVE-2016-2516",
    "CVE-2017-1000367",
    "CVE-2016-1548",
    "CVE-2017-1000364",
    "CVE-2016-1547",
    "CVE-2016-1550",
    "CVE-2016-2518",
    "CVE-2016-2517",
    "CVE-2016-2519",
    "CVE-2016-1549",
    "CVE-2016-1551",
    "CVE-2017-1000369"
  );
  script_bugtraq_id(101255, 101256);
  script_xref(name:"JSA", value:"JSA10826");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Juniper Junos Space < 17.1R1 Multiple Vulnerabilities (JSA10826)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Junos
Space running on the remote device is < 17.1R1, and is therefore
affected by multiple vulnerabilities.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10826&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d563772");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space version 17.1R1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7494");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba is_known_pipename() Arbitrary Module Load');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'17.1R1', severity:SECURITY_HOLE);
