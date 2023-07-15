#TRUSTED 1da5754b6f2e97880dd401466d37d3b07a9fba8735fa5fef70a95d22bacc02fcdbbb04fe06877ed3192354d72c0dfc34af951f7228e31e4b3ad06a11f1046d7d744a7c7f08029c47242544438a1bbb4b535e163b6ba63b044777c2c9249ef662b4a7fb477ddcbdc5e81ada28329ba03e8e75bfd19107ffa7b10e0bda79f875c219cb7739773bbdc041ca094d012bdc2b395b24a5a02df6bdb31edbbf60c86a36452e70b04fa94a54bc330488541f34fb4febe17ddb5c8da28d20e4f528e0dcb2bce1aacc2927c953ab5445032a639f2b375b65e722daad0c7399d04c863299071aae5652e693deb06470ebb802073c9b6d41465a8b440665ea2b4876f66fe6f610c22534bb6a1ff114631cd3f88df250f805f9324036ba0982a0106a17d03acbf53130d5202b5b96b9e8eec3c1211781e4759d89951ed4bfc15c8b3c66eec68beb7a0cbbb2d9a3a877cf92137b8f2b3d8263fea36f35a2f24c3705e799b25356eff2815f3b901b4fbcfc50bc409a2110ec26a007a4440bc02a8e4b3787d34ab05d64188cc514fc8a2f080a4a568042cb1967a7537a99a277c40f1e8bf9bdc062fe6af2980e0f8aef64849ac01d45bd39512bf669546459f0f03ee8d3a5f0d04cb6ec7ce83843630a48230667aab121e91d218581526fc916e3d6ed9628379d0cbb69b87219b429efb7c6f9bd3a2e678f40624bd672e7485a133829b77f71445d
#TRUST-RSA-SHA256 32dd4f59fef9f7acae722bf6f9a7ea475a003983ae56e2b674d0a2d1fd945bca632dc8a4a10649f73d07d6265325706940bdff5325b24a5aa66c82cc473a67d8e04ef98b1b11f81fdec29c165a10fa645fea3e1ae5e94220964c397f1c4932f069ac0d0463eca3f2bdb3148868899c175bdb2811ea4f9acbb29739fc92fd4a87e35560e0e755217ab521b3f50f1c20b2c9309392e518e29a0c08648728063c16f8dfb8914052ac6b9a79a5a1aa8d9ffa2ed52afec63f21c9c2b261b2ece9c65eb08debd680c84bafa53d645e9cc0e40d7179da87ea418d603eb8a26d8e20b6d7b69352de48446c34f4c52fa2eb956d1c44839abc4b97a5dc353a048315f2f8340f1b7d419b8bbb7f91f8abe572cda3a6a259227e92d9d70fc5fdd8764833b18ff1621835f9d478e8c067dc67d43cf70042b07e6c92f88c9e3378312b79ebb2ce789ba3672b15638cdd72b5b58d7f035e51518daeb44f3edd74bc8455a1a93b021dbe7db5866e0f19cd48b9f423c7e72b9f8428004f1ba5539ed80d243c5911de756e74f55c7ee04c64254243be32ed5485a22a96d6b3ef5645330361de8d1872023e21c2627cb8d734b8edaa783fd6b6e01ea7d1d3049dd667d321bbfc461bc65c251724e90e18f5c638f68d6a755d70e5d0fc92309dbaf27411ac178933411cda9645790d3325a118c436d78f088f76724e8c7169c94671352a2c0ad6773426
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(93737);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/20");

  script_cve_id("CVE-2016-6415");
  script_bugtraq_id(93003);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb29204");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160916-ikev1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/09");

  script_name(english:"Cisco IOS XE IKEv1 Packet Handling Remote Information Disclosure (cisco-sa-20160916-ikev1) (BENIGNCERTAIN)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
IOS XE software running on the remote device is affected by an
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if ( ver == "3.1.0S" ) flag++;
else if ( ver == "3.1.1S" ) flag++;
else if ( ver == "3.1.2S" ) flag++;
else if ( ver == "3.1.3aS" ) flag++;
else if ( ver == "3.1.4aS" ) flag++;
else if ( ver == "3.1.4S" ) flag++;
else if ( ver == "3.2.1S" ) flag++;
else if ( ver == "3.2.2S" ) flag++;
else if ( ver == "3.3.0S" ) flag++;
else if ( ver == "3.3.0SG" ) flag++;
else if ( ver == "3.3.1S" ) flag++;
else if ( ver == "3.3.1SG" ) flag++;
else if ( ver == "3.3.2S" ) flag++;
else if ( ver == "3.3.2SG" ) flag++;
else if ( ver == "3.4.0aS" ) flag++;
else if ( ver == "3.4.0S" ) flag++;
else if ( ver == "3.4.0SG" ) flag++;
else if ( ver == "3.4.1S" ) flag++;
else if ( ver == "3.4.1SG" ) flag++;
else if ( ver == "3.4.2S" ) flag++;
else if ( ver == "3.4.2SG" ) flag++;
else if ( ver == "3.4.3S" ) flag++;
else if ( ver == "3.4.3SG" ) flag++;
else if ( ver == "3.4.4S" ) flag++;
else if ( ver == "3.4.4SG" ) flag++;
else if ( ver == "3.4.5S" ) flag++;
else if ( ver == "3.4.5SG" ) flag++;
else if ( ver == "3.4.6S" ) flag++;
else if ( ver == "3.4.6SG" ) flag++;
else if ( ver == "3.4.7SG" ) flag++;
else if ( ver == "3.5.0E" ) flag++;
else if ( ver == "3.5.0S" ) flag++;
else if ( ver == "3.5.1E" ) flag++;
else if ( ver == "3.5.1S" ) flag++;
else if ( ver == "3.5.2E" ) flag++;
else if ( ver == "3.5.2S" ) flag++;
else if ( ver == "3.5.3E" ) flag++;
else if ( ver == "3.6.0E" ) flag++;
else if ( ver == "3.6.0S" ) flag++;
else if ( ver == "3.6.1E" ) flag++;
else if ( ver == "3.6.1S" ) flag++;
else if ( ver == "3.6.2aE" ) flag++;
else if ( ver == "3.6.2E" ) flag++;
else if ( ver == "3.6.2S" ) flag++;
else if ( ver == "3.6.4E" ) flag++;
else if ( ver == "3.6.5E" ) flag++;
else if ( ver == "3.7.0E" ) flag++;
else if ( ver == "3.7.0S" ) flag++;
else if ( ver == "3.7.1E" ) flag++;
else if ( ver == "3.7.1S" ) flag++;
else if ( ver == "3.7.2E" ) flag++;
else if ( ver == "3.7.2S" ) flag++;
else if ( ver == "3.7.2tS" ) flag++;
else if ( ver == "3.7.3E" ) flag++;
else if ( ver == "3.7.3S" ) flag++;
else if ( ver == "3.7.4aS" ) flag++;
else if ( ver == "3.7.4S" ) flag++;
else if ( ver == "3.7.5E" ) flag++;
else if ( ver == "3.7.5S" ) flag++;
else if ( ver == "3.7.6S" ) flag++;
else if ( ver == "3.7.7S" ) flag++;
else if ( ver == "3.8.0E" ) flag++;
else if ( ver == "3.8.0S" ) flag++;
else if ( ver == "3.8.1E" ) flag++;
else if ( ver == "3.8.1S" ) flag++;
else if ( ver == "3.8.2E" ) flag++;
else if ( ver == "3.8.2S" ) flag++;
else if ( ver == "3.9.0aS" ) flag++;
else if ( ver == "3.9.0E" ) flag++;
else if ( ver == "3.9.0S" ) flag++;
else if ( ver == "3.9.1aS" ) flag++;
else if ( ver == "3.9.1S" ) flag++;
else if ( ver == "3.9.2S" ) flag++;
else if ( ver == "3.10.0S" ) flag++;
else if ( ver == "3.10.1S" ) flag++;
else if ( ver == "3.10.1xbS" ) flag++;
else if ( ver == "3.10.2S" ) flag++;
else if ( ver == "3.10.2tS" ) flag++;
else if ( ver == "3.10.3S" ) flag++;
else if ( ver == "3.10.4S" ) flag++;
else if ( ver == "3.10.5S" ) flag++;
else if ( ver == "3.10.6S" ) flag++;
else if ( ver == "3.10.7S" ) flag++;
else if ( ver == "3.11.0S" ) flag++;
else if ( ver == "3.11.1S" ) flag++;
else if ( ver == "3.11.2S" ) flag++;
else if ( ver == "3.11.3S" ) flag++;
else if ( ver == "3.11.4S" ) flag++;
else if ( ver == "3.12.0aS" ) flag++;
else if ( ver == "3.12.0S" ) flag++;
else if ( ver == "3.12.1S" ) flag++;
else if ( ver == "3.12.2S" ) flag++;
else if ( ver == "3.12.3S" ) flag++;
else if ( ver == "3.12.4S" ) flag++;
else if ( ver == "3.13.0aS" ) flag++;
else if ( ver == "3.13.0S" ) flag++;
else if ( ver == "3.13.1S" ) flag++;
else if ( ver == "3.13.2aS" ) flag++;
else if ( ver == "3.13.2S" ) flag++;
else if ( ver == "3.13.3S" ) flag++;
else if ( ver == "3.13.4S" ) flag++;
else if ( ver == "3.13.5aS" ) flag++;
else if ( ver == "3.13.5S" ) flag++;
else if ( ver == "3.13.6aS" ) flag++;
else if ( ver == "3.13.6S" ) flag++;
else if ( ver == "3.14.0S" ) flag++;
else if ( ver == "3.14.1S" ) flag++;
else if ( ver == "3.14.2S" ) flag++;
else if ( ver == "3.14.3S" ) flag++;
else if ( ver == "3.14.4S" ) flag++;
else if ( ver == "3.15.0S" ) flag++;
else if ( ver == "3.15.1cS" ) flag++;
else if ( ver == "3.15.1S" ) flag++;
else if ( ver == "3.15.2S" ) flag++;
else if ( ver == "3.15.3S" ) flag++;
else if ( ver == "3.16.0cS" ) flag++;
else if ( ver == "3.16.0S" ) flag++;
else if ( ver == "3.16.1aS" ) flag++;
else if ( ver == "3.16.1S" ) flag++;
else if ( ver == "3.16.2aS" ) flag++;
else if ( ver == "3.16.2S" ) flag++;
else if ( ver == "3.17.0S" ) flag++;
else if ( ver == "3.17.1S" ) flag++;
else if ( ver == "3.17.2S" ) flag++;
else if ( ver == "3.18.0S" ) flag++;
else if ( ver == "3.18.1S" ) flag++;
else if ( ver == "3.18.2S" ) flag++;

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
          flag = 1;
          cmd_list = make_list(cmd_list, "show ip sockets");
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
    port     : 0,
    severity : SECURITY_WARNING,
    override : override,
    version  : ver,
    bug_id   : 'CSCvb29204',
    cmds     : cmd_list
  );
}
else audit(AUDIT_HOST_NOT, "affected");
