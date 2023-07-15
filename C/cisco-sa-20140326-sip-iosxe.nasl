#TRUSTED 444e16e612c8292b2505869f32235ac0a69587b90be3cd499d4a4dd2f941b4cdbef8345468ae5f7e252dda61c8c6356d1f3c431690a1c43f055a1f133e105655190f6acd8077d89990a7237d37e666fa267f9f8b1ab1cde9ee1d480198bdc96b8089ef8734e8b4a6812867b400684e10b00cf07017616bf01773f4f669b2aa1aaaa1cd7996597125be326fef8df67096c1bb5dd32044c5213c45d121c3b15e68c1421bff5c1b024a908ce258cc0ab0a74a37743ab124b376f4af448c4bbf57c76afe3d39826255f7847728f0e0414564d9ebb53ad14faf115f76bbc640ab422e67f4de90522e10464a58fee1c1bea105032b87b61eac56c5f2f180768c360c9fa6a97cb9811855926ad3f166e23653cd3921262d50d1279e8c5f7012076795bc305d17d73ccd11211a4dc608d730d7b22fc13877bf8d2fa8abc21cc14ed5a04a263b249a3877faaf9c02422a78a1fb22514372bd1b5dc00041d42f2cc23a097f8473fd01fb824be2e46fd2deaeb5a91db22655c482f28ad3ef718e250154a4fac6a110820e3e476913c70194e0ed5710ace64bb6d060d0439b4605f9cfd5178bbf7ddfc395d73fb6fa448ebbe3691e583ea3c20b71d0ee4ab89deda92e6c98ce18e769b2f46a695d9ca724cc7d307beb1717abc2044a7ce1346851a57f7c68807a17486515fbba7d5ce29a42dd85ca8349fb397d65f26525e6595b754c3a9816
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73346);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-2106");
  script_bugtraq_id(66465);
  script_xref(name:"CISCO-BUG-ID", value:"CSCug45898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-sip");

  script_name(english:"Cisco IOS XE Software Session Initiation Protocol Denial of Service (cisco-sa-20140326-sip)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the Session Initiation Protocol (SIP) implementation.
An unauthenticated, remote attacker could potentially exploit this
issue to cause a denial of service.

Note that this issue only affects hosts configured to process SIP
messages. SIP is not enabled by default on newer IOS XE versions.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0dba6e85");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-sip.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}


include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
report = "";
cbi = "CSCug45898";
fixed_ver = "3.10.2S";

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

if (ver == '3.10.0S' || ver == '3.10.0aS' || ver == '3.10.1S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (
           (preg(multiline:TRUE, pattern:"CCSIP_UDP_SOCKET", string:buf)) ||
           (preg(multiline:TRUE, pattern:"CCSIP_TCP_SOCKET", string:buf))
         ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
