#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121068);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id(
    "CVE-2017-0861",
    "CVE-2017-2619",
    "CVE-2017-3136",
    "CVE-2017-3137",
    "CVE-2017-3142",
    "CVE-2017-3143",
    "CVE-2017-3145",
    "CVE-2017-15265",
    "CVE-2017-1000364",
    "CVE-2017-1000366",
    "CVE-2017-1000379",
    "CVE-2018-1050",
    "CVE-2018-1064",
    "CVE-2018-1124",
    "CVE-2018-1126",
    "CVE-2018-3620",
    "CVE-2018-3693",
    "CVE-2018-5390",
    "CVE-2018-5391",
    "CVE-2018-5740",
    "CVE-2018-5748",
    "CVE-2018-7566",
    "CVE-2018-10301",
    "CVE-2018-10897",
    "CVE-2018-10901",
    "CVE-2018-10911",
    "CVE-2018-12020",
    "CVE-2018-12384",
    "CVE-2018-14634",
    "CVE-2018-1000004"
  );

  script_name(english:"Juniper Junos Space 18.4.x < 18.4R1 Multiple Vulnerabilities (JSA10917)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is 18.4.x prior to 18.4R1. It is, therefore, affected by
multiple vulnerabilities : 

  - An integer overflow issue exists in procps-ng. This is
    related to CVE-2018-1124. (CVE-2018-1126)

  - A directory traversal issue exits in reposync, a part
    of yum-utils.tory configuration files. If an attacker
    controls a repository, they may be able to copy files
    outside of the destination directory on the targeted
    system via path traversal. (CVE-2018-10897)

  - An integer overflow flaw was found in the Linux 
    kernel's create_elf_tables() function. An unprivileged
    local user with access to SUID binary could use this
    flaw to escalate their privileges on the system.
    (CVE-2018-14634)

Additionally, Junos Space is affected by several other
vulnerabilities exist as noted in the vendor advisory.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10917");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space 18.4R1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10897");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-1126");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solaris RSH Stack Clash Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

# since 18.3R1 was released in the same advisory, we are just
# checking 18.4.x here
check_junos_space(ver:ver, min:'18.4', fix:'18.4R1', severity:SECURITY_HOLE);
