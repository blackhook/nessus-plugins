#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126510);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id(
    "CVE-2016-10009",
    "CVE-2016-10010",
    "CVE-2016-10011",
    "CVE-2016-10012",
    "CVE-2017-15906",
    "CVE-2018-0046"
  );
  script_bugtraq_id(
    94968,
    94972,
    94975,
    94977,
    101552,
    105566
  );
  script_xref(name:"JSA", value:"JSA10880");

  script_name(english:"Juniper Junos Space < 18.2R1 Multiple Vulnerabilities (JSA10880)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Junos
Space running on the remote device is < 18.2R1, and is therefore
affected by multiple vulnerabilities:

  - Due to untrusted search path vulnerability in ssh-agent.c in ssh-agent
    in OpenSSH before 7.4, unauthenticated, remote attacker can execute execute
    arbitrary local PKCS#11 modules by leveraging control over a forwarded 
    agent-socket. (CVE-2016-10009)
   
  - In OpenSSH before 7.4, an authenticated local attacker can escalate 
    privileges via unspecified vectors, related to serverloop.c. 
    (CVE-2016-10010)
    
  - authfile.c in sshd in OpenSSH before 7.4 does not properly consider the 
    effects of realloc on buffer contents. an authenticated local attacker 
    can obtain sensitive private-key information by leveraging access to a 
    privilege-separated child process. (CVE-2016-10011)
    
  - In sshd in OpenSSH before 7.4, a local attacker can gain privileges by 
    leveraging access to a sandboxed privilege-separation process due to a
    bounds check that's enforced by all by the shared memory manager. 
    (CVE-2016-10012)
    
  - The process_open function in sftp-server.c in OpenSSH before 7.6 does not
    properly prevent write operations in readonly mode, which allows local 
    attackers to create zero-length files. (CVE-2017-15906)
    
  - A reflected cross-site scripting vulnerability in OpenNMS included
    with Juniper Networks Junos Space may allow the stealing of sensitive
    information or session credentials from Junos Space administrators or
    perform administrative actions.  (CVE-2018-0046)");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10880");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space version 18.2R1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10009");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-10012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");

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

include('junos.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'18.2R1', severity:SECURITY_HOLE);
