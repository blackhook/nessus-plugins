#TRUSTED a600e6e6446568b8c596a26e09a708e3fa7ed48e119fb79b7e1a6938d6be570d72b7f6194f9090632b603ca559ef048a925dacfbe12c2bedc44c42b98df21b3e9fb44984fd3db462140b0d1b2847b885079787c9981fdacfdf8776135311cae08d0b2d89e5e08c07b1e71ce25551818629b274acd4aafacd3896ee452d82d909c10056be3efc187b3bfd6b3f03784c5301afe0c4e5229faf548a1a07c89027c05ce5570747fc0917972985b16d8dec99f7d91bec01cdb5c7ea0e30e75801dda97a3e724ebd694092f653bd94508f2ba5aecf4c32337892f555d2d07ec61edd6b6afb0634e8faeba9061ddaa94ec5b22cf6ce776d76c046ca1b34d06b3f35702f52239cfeb7727002daa44c9b9bd831f3050fe7aca4f61f7b1aa56b1d227b55ac188b3faccbf41159ca9b8240f1ac98273a36f681c4213b566f65d6800d5fac96a3d2e2f4968a70004efccbd571ba3e2fc074b28523e2428e77059f4b42e9d42716bf5f367794b85a167b988b2daf7a3495796b099aa608b04e0c5ad3e5a9fd2c5b51ed35eb7f4c4b3bf8566c7fe86b50ef0f0fb5ef3b17392cb809b7e4176910521f3e7dfca56f37111d13bb49814fcfd182907fe9d4020e3be1dbbf2d000efe06b8e8aec53336e01e6cfec5d45847fe6c59c76f2f55b821c85c61447cc8a3a6a85f4197bde2d7aac04fb2ce7d106c988ea31314e542dba70972193bb48136dd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88989);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0076",
    "CVE-2014-0198",
    "CVE-2014-0224"
  );
  script_bugtraq_id(
    66363,
    66801,
    67193,
    67899
  );
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22487");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140605-openssl");

  script_name(english:"Cisco IOS XE Multiple OpenSSL Vulnerabilities (CSCup22487)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing a vendor-supplied security
patch, and its web user interface is configured to use HTTPS. It is,
therefore, affected by the following vulnerabilities in the bundled
OpenSSL library :

  - An error exists in the ssl3_read_bytes() function that
    could allow data to be injected into other sessions or
    allow denial of service attacks. Note this issue is only
    exploitable if 'SSL_MODE_RELEASE_BUFFERS' is enabled.
    (CVE-2010-5298)

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An error exists in the do_ssl3_write() function that
    could allow a NULL pointer to be dereferenced leading to
    denial of service attacks. Note this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An unspecified error exists that could allow an attacker
    to cause usage of weak keying material leading to
    simplified man-in-the-middle attacks. (CVE-2014-0224)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aa6a7e6");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCup22487");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup22487.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0224");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
flag     = 0;
override = TRUE;

# Only 3.11.0S, 3.11.1S and 3.12.0S are affected
if (version == "3.11.0S") flag++;
if (version == "3.11.1S") flag++;
if (version == "3.12.0S") flag++;

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS XE", version);

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_all", "show running-config all");

  if (check_cisco_result(buf))
  {
    override = FALSE;

    if (
      # Web UI HTTPS
      preg(string:buf, pattern:"^ip http secure-server", multiline:TRUE) ||
      # SSL VPN
      cisco_check_sections(
        config:buf,
        section_regex:"^crypto ssl profile ",
        config_regex:'^\\s*no shutdown$'
      ) ||
      # HTTPS client feature / Voice-XML HTTPS client
      preg(string:buf, pattern:"^(ip )?http client secure-", multiline:TRUE) ||
      # CNS feature
      preg(string:buf, pattern:"^cns (config|exec|event) .* encrypt", multiline:TRUE) ||
      # Settlement for Packet Telephony feature
      cisco_check_sections(
        config:buf,
        section_regex:"^settlement ",
        config_regex:make_list('^\\s*url https:', '^\\s*no shutdown$')
      ) ||
      # CMTS billing feature
      preg(string:buf, pattern:"^cable metering .* secure", multiline:TRUE)
    ) flag++;
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override = TRUE;
  }

  if (!flag)
    audit(AUDIT_HOST_NOT, "affected because it does not appear as though any service utilizing the OpenSSL library is enabled");  
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID      : CSCup22487' +
    '\n  Installed release : ' + version +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
