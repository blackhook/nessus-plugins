#TRUSTED 55ba1dfc601ebdf21143c9b81058907ec262bd7b956ca3fb2af41708c6ee8dfaa7f1b951a3f147c8500186fa2869b79fe9b3a667d852ba7e4576149fb4bafc324dc440629f586bd502998cf37e1ee967e75970aded20ab4fcc1415453ee4b6c827752c0c35e005fd7694e3e662f14ae6142cdecf47f774cb29415fbc161d6ef1dd3a940aea18a6d22f8243edda4ffd29bc61f9575852dc4da333bf70e645ba47c9e69c6e4c6c928b7c12e52a57876aaf55dd6a9028eae6224727c80d66dd78b2c96a7bdfe58be83f262d0685f7354b7f7e877693fa16c690a389d02c0fff08ed8b34aca10d97cfb09cb8c7719f454cf064b82cd2a265a6b9c3b2ef494ea24e6aff0c4a471e8421f517724e085251c4711a5c0399483075ea281bb2e6aca83a9a3556518be51d17d78b6d8e888081cd4266662b86a53f3a7da2d333cbca7677399a88e93669dc3af29a939ada7042551b357f42afc16f8b6af44b24f88e5fc1add4074f3a170369d488b2807f1cf14839f6c5ba55b02f11da9250854f6e62b67dd9f56056379d6e685293fafc2db2801f652840c3aab39b209aedd6f9426cb760990d153ad7b64f789f39b4e4e0a3ff885c48861c75cc72a3103a4af2b0fbcc490f4bdb41efddbd0c1f6dcf45e3667ff55d5a3aec152ee7aa6abb10dac5a6dfbaffe840e5011f351ae1d55502fc6cb7ccb61d7ab18f173a70d0cf27de3fdb8d5f
#TRUST-RSA-SHA256 1445ed0cf5054c9fbf2638a6e9bf327c24944bc6bd3aa8602073ce0eeeac4570e102f98c0a8487000974cc3b763b39c2b92acbb7e20ac4e5173a21b620e6271d603b8c810cff1d1bfea2dc2f3a9e954e42b69d9fbe5174868ad3b47ae80143c63a6eeb0b1aa95f12077be197eaa8898f01b4fea3226faed61b67ec521abebb4ce05e9a6365030f5684f81194c31e78c80f7b1295868318656a9be47a1110d764a0e6065a63ed558bedb75ba9b5f1a00d7cdd0fa6c1acd70b427c206b748767d57a70f7682a98ff6173df3c77ac717fdcf87c963de2a51206317edfae251df0cfb135ec400a6dd9c346c172a8fd506b8a929944411f056134e64f2e205671b760cdd2c93a86b0eb63401f0b504d70f062017463b3e2baf258777f550a7673cd118c47cfa1ab56c94fc4a398b63ce21718412d99cf73a19a0488eeb8a4a236c9301cc29b62a1b16f7551bdb4a4adcbf3bed22040c564e0fe5029ee11a17efdfe29ee6b2909becaaab19d7c50881950340dea575a5fb77329d3fd690248f5b0a41efb706a34921deda0dd174904ff40f2b3ad764ea42758c54904d97a7aed28fc52d45559f2a477a51b63fdc221fdfad101a3236cb0b5a850699b25e8b98f58e56bdc00189cb8a4f6923b56ee185a6c2678d675f6e38abff883a957453152baa52346161fa1d6453028e0ec47b985958e3adb7e0f05204d59a7f571b4c12830af6b
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(96047);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2016-6461");
  script_bugtraq_id(94365);
  script_xref(name:"CISCO-BUG-ID", value:"CSCva38556");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20161116-asa");
  script_xref(name:"IAVB", value:"2016-B-0167-S");

  script_name(english:"Cisco ASA Web Interface Remote XML Command Injection (cisco-sa-20161116-asa)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by an XML command injection vulnerability in the
web-based management interface due to improper validation of
user-supplied input. An unauthenticated, remote attacker can exploit
this, via specially crafted XML input, to inject arbitrary XML
commands, resulting in an impact to the integrity of the device.

Note that Cisco considers this vulnerability to be low/medium
severity, and as a result the existing check information may not be
complete from the vendor. For additional verification, please contact
TAC Cisco support.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161116-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbeb50dc");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCva38556");
  # https://www.cisco.com/c/en/us/support/web/tsd-cisco-worldwide-contacts.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?741a3b85");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCva38556.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');

version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

cbi = 'CSCva38556';

vulniosarray = make_array(
  "9.1", make_list("9.1(6.10)",
                   "9.1(7.4)",
                   "9.1(7.6)",
                   "9.1(7.7)",
                   "9.1(7.9)",
                   "9.1(7.11)"),
  "9.2", make_list("9.2(1)",
                   "9.2(2)",
                   "9.2(2.4)",
                   "9.2(2.7)",
                   "9.2(2.8)",
                   "9.2(3)",
                   "9.2(3.3)",
                   "9.2(3.4)",
                   "9.2(0.0)",
                   "9.2(0.104)",
                   "9.2(3.1)",
                   "9.2(4)",
                   "9.2(4.2)",
                   "9.2(4.4)",
                   "9.2(4.8)",
                   "9.2(4.10)",
                   "9.2(4.13)",
                   "9.2(4.14)",
                   "9.2(4.16)",
                   "9.2(4.17)"),
  "9.3", make_list("9.3(1)",
                   "9.3(1.1)",
                   "9.3(1.105)",
                   "9.3(1.50)",
                   "9.3(2)",
                   "9.3(2.100)",
                   "9.3(2.2)",
                   "9.3(2.243)",
                   "9.3(3)",
                   "9.3(3.1)",
                   "9.3(3.2)",
                   "9.3(3.5)",
                   "9.3(3.6)",
                   "9.3(3.9)",
                   "9.3(3.10)",
                   "9.3(3.11)",
                   "9.3(5)"),
  "9.4", make_list("9.4(1)",
                   "9.4(0.115)",
                   "9.4(1.1)",
                   "9.4(1.2)",
                   "9.4(1.3)",
                   "9.4(1.5)",
                   "9.4(2)",
                   "9.4(2.3)",
                   "9.4(3)",
                   "9.4(3.3)",
                   "9.4(3.4)",
                   "9.4(3.6)",
                   "9.4(3.8)",
                   "9.4(3.11)",
                   "9.4(3.12)"),
  "9.5", make_list("9.5(1)",
                   "9.5(2)",
                   "9.5(2.6)",
                   "9.5(2.10)",
                   "9.5(2.14)")
);

override = FALSE;
flag = FALSE;

majorversion = ereg_replace(pattern:"^([0-9.]+).*", string:version, replace:"\1");
vulnios = vulniosarray[majorversion];

foreach vulnver (vulnios)
{
  if (!check_asa_release(version:version, patched:vulnver) && !check_asa_release(version:vulnver, patched:version))
  {
    if (get_kb_item("Host/local_checks_enabled"))
      buf = cisco_command_kb_item("Host/Cisco/Config/show running-config", "show running-config");

    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^ *http server enable", string:buf))
        flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;

    if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the HTTP server is not enabled");
  }
}

if (flag || override)
  {
    security_report_cisco(
      port     : 0,
      override : override,
      severity : SECURITY_WARNING,
      version  : version,
      bug_id   : cbi,
      cmds     : make_list("show running-config")
      );
  }
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
