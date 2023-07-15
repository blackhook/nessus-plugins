#TRUSTED 25b029a46acda19d77cc7d5fd9a0b5008d63d232ee166143d1b35725cabee1ce415735208653e5ffe4af9b20927a023c92ebf3f2ef39bb617da8bda1e662460b15be389d2a15d27b83f4b7ab5becaeee961953012f327a2d4b0ff2d94e3df182ba9a6d14790f5c3c909e96b3897b14df5b222d84f6983d72d0794c4350212113b023b65a35a8b42ba372361ca009f8ff441cc472ef11f5d74ec7c4e437f7ac6f5faa693cf2ab86ad718816efdca6145ddcbf7153734e5fa14593f1d433199651c44827c6c5c6960ab98e76e9be0ce52abab66175189665260e0d7991710d6214f4df1a271b511d54d401a96420a048ada6f3d9e1ac600f4812d7127e85731fa6ec5dc9b3cc0bf4689b43cfcc4d70ee7b1c9b0a3c90d2af1354cbaa5cf7fb1d4f24160558887e07abe416be17808ab0c6bc8dae037a31b72f5e72f61a5e200a726d7d5e38725641e47e3ae55b0aad7c28d56ceae4bd09244ec1937badf42923fac68d73e3e20c1f3a4620396b1a5a2b88a9f824f18aa23779b912bc8c8b3051ab2e4eec0a7779d0e07b34f2330d2fd24d5430ac0e851da80901b24a5e55bed89bce0ca14efd3a595ecd8b23c25d80e99f30a0468424da75f579d6eec7573a4964c3f489f569f792922ae676616b21118393470872d6559a93d6bd6f59dd77de5ed1817cd159702529cf09e24b7023a7917cf9c84765e770934024b7b0c1b3abad
#TRUST-RSA-SHA256 702a5a4cf7a30b6df0c7bedab986153ee91c05dc627e1b0ac8b35ca330915cd3eb8ff438626f9fc52d82c54aca893304d7b04fe32a9959e1993aee4524c7f474a208c7482741ff38862a4b1d07aea1e836188ea7ba55196adc43f17136cab12bfe6b4c6a9b59b2daae519540aa19bb2da0a12d1d9e2ce4879e62304c18cc08bd6dea6ee5a0b57ad47570ee17239cffe9309dcfbd72e46346e4f83928f285ac94d8af3b0252b64bffafb7c44162eca10775250d976a845d6d73874b6a6a473d0cfc7dce42e31cc63ed1837f58154e485db93a23cc37221173638bcc18b6508fdb17fa2f29367bb4055dd19e99e28f9fc155c74136ba205cc8bb590b153d07b0a58d6c72c3ccfec6c378c3b5c0f653aa9ed048cc205530ffe56cab165d9ea0a1083eebe733e41f95e814ee6a00abd2406790ea1f8ec37b14cecf57f12cbac159d419b64e91e47eea6e2a061a0b7228885567793e04926975efe41998d21a7dd22b35c3bc69c85b2e932abd015ddc0a278ae16f66997fdc031dc9567d5331c52f6ee55d97aa22cd0e1699043fbfa598ee0e7232bcdb8b05c8e08472c0bbc7a3fd5197e9c721c9f70a983106e67b343e74124af9e654b24674e6f71b2558b98b9e0c73db8835d08868119f92b9aef747356fd1845aabbe039e61e43eca8bb6b31885af1ff1ec64120cc54340e13984e911ced76384984cb5d274c7988e66e74413b1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93738);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/20");

  script_cve_id("CVE-2016-6415");
  script_bugtraq_id(93003);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb29204");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160916-ikev1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/09");

  script_name(english:"Cisco IOS XR IKEv1 Packet Handling Remote Information Disclosure (cisco-sa-20160916-ikev1) (BENIGNCERTAIN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XR software running on the remote device is affected by an
information disclosure vulnerability, known as BENIGNCERTAIN, in the
Internet Key Exchange version 1 (IKEv1) subsystem due to improper
handling of IKEv1 security negotiation requests. An unauthenticated,
remote attacker can exploit this issue, via a specially crafted IKEv1
packet, to disclose memory contents, resulting in the disclosure of
confidential information including credentials and configuration
settings.

BENIGNCERTAIN is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2016/08/14 by a group known as the Shadow
Brokers.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160916-ikev1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7f2c76c");
  # https://www.riskbasedsecurity.com/2016/08/the-shadow-brokers-lifting-the-shadows-of-the-nsas-equation-group/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c7e0cf3");
  script_set_attribute(attribute:"see_also", value:"https://blogs.cisco.com/security/shadow-brokers");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvb29204.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6415");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

flag     = FALSE;
override = FALSE;

if (
  version =~ "^4\.3\."
  ||
  version =~ "^5\.0\."
  ||
  version =~ "^5\.1\."
  ||
  version =~ "^5\.2\."
)
  flag = TRUE;

# Check that IKEv1 config or IKEv1 is running
cmd_list = make_list();
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;

  # Check for condition 1, IKEv1 config
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config","show running-config");
  if (check_cisco_result(buf))
  {
    if (
      "crypto gdoi" >< buf
      ||
      "crypto map" >< buf
      ||
      "tunnel protection ipsec" >< buf
    )
    {
      flag = 1;
      cmd_list = make_list("show running-config");
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  # Check for condition 2, IKEv1 is running
  if (flag)
  {
    flag = 0;

    pat = "(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+(500|848|4500|4848)\s";
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
    if (!flag)
    {
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        )
        {
          cmd_list = make_list(cmd_list, "show ip sockets");
          flag = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }

    if (!flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_udp","show udp");
      if (check_cisco_result(buf))
      {
        if (
          preg(multiline:TRUE, pattern:pat, string:buf)
        )
        {
          flag = 1;
          cmd_list = make_list(cmd_list, "show udp");
        }
      }
      else if (cisco_needs_enable(buf))
      {
        flag = 1;
        override = 1;
      }
    }
  }
}

if (flag)
{
  security_report_cisco(
    port     : port,
    severity : SECURITY_WARNING,
    override : override,
    version  : version,
    bug_id   : "CSCvb29204",
    cmds     : cmd_list
  );
}
else audit(AUDIT_HOST_NOT, "affected");
