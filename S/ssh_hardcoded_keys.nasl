#TRUSTED 951029e86c538e59227d577263cc1fd4c12418560940df697f68a5253d361a0c768bc42af5fae572146a1f45900e4c7048a284d74d8a193731871bc4228b8da99999b3327f0e5bd9081bc79abff2945f59b3062b2a6f0e8850fd6623c17799e408c5e9672304016d8757f10cacba5840af39ed433101177c6eb2aaf6d023b3272cf3bdc10ab8833c2393ffe7c189fb07e389232193ef595510090d36370c9475d67df7bef5ba849a2eb0bb9851779fd32a7f46a177ec9db24d2f478134cec0ef66a61df2e2546e9c25b8d5ae18f31fb8e6586b4e7f73c61cc7362c78d7b342aa703d8232dcaef670037540681c37986c0c16704b713438271f683ec30ae8cd4ee75f178da35b8b12095066261b5676dc68f4c0e7d265c16c0f62c2f84ec67b71ee761ac9af8da11d019c7fd622e35ceaf040a4e02b71f77c1b76c3af582371b43d4b8d4f10e95856442528fe2390e9b36b70f21e8cd6f95fc1f9291d8a12ccf6443a3be2f38fc6ef52ae13c3c7e76e07043089370c860f687d8d460b9a2f5ca99dd24ceba97be6e88ee3de6179088cc88c79a1075223bdc785fe0fd7bad3758e72206db9dbd8e79d2717412339232919ee7d0c69e88349ad9ff1139ac1c8337ebe6ea7fc9f8c65b2cf71e95af32d34f4c99b25b7d328716dd44e0a80f16449c11a73ab2de812231dc6c0d7a9774c2d7b7ef7dbf9c524bb98cf71a1d4155a87af
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121007);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id(
    "CVE-2015-6358",
    "CVE-2015-7255",
    "CVE-2015-7256",
    "CVE-2015-7276",
    "CVE-2015-8251"
  );

  script_name(english:"SSH Known Hard Coded Private Keys");
  script_summary(english:"Determines if known hard coded SSH private keys are in use.");

  script_set_attribute(attribute:"synopsis", value:
"Known SSH private keys in use.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a service that is using a publicly known SSH private key.
An attacker may use this key to decrypt intercepted traffic between users and the device.
A remote attacker can also perform a man-in-the-middle attack in order to gain access to the
system or modify data in transit.");
  # https://sec-consult.com/en/blog/2015/11/house-of-keys-industry-wide-https/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48f09948");
  script_set_attribute(attribute:"see_also", value:"https://github.com/sec-consult/houseofkeys");
  script_set_attribute(attribute:"see_also", value:"https://www.kb.cert.org/vuls/id/566724/");
  script_set_attribute(attribute:"solution", value:
"Where possible, change the SSH host keys so that they are unique to the device
or contact vendor for guidance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7255");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_get_info2.inc");
include("ssh_func.inc");
include("ssh_lib.inc");
include("ssh_hardcoded_fingerprints.inc");

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# get md5 fingerprint from ssh_detect.nasl
fingerprint_md5 = get_kb_item("SSH/Fingerprint/ssh-rsa/"+port);
if(!fingerprint_md5) fingerprint_md5 = get_kb_item("SSH/Fingerprint/ssh-dss/"+port);
if(!fingerprint_md5) fingerprint_md5 = get_kb_item("SSH/Fingerprint/ecdsa/"+port);

# get sha256 fingerprint from ssh_detect.nasl
fingerprint_sha256 = get_kb_item("SSH/Fingerprint/sha256/ssh-rsa/"+port);
if(!fingerprint_sha256) fingerprint_sha256 = get_kb_item("SSH/Fingerprint/sha256/ssh-dss/"+port);
if(!fingerprint_sha256) fingerprint_sha256 = get_kb_item("SSH/Fingerprint/sha256/ecdsa/"+port);

# both fingerprints are expected
if (!fingerprint_md5 || !fingerprint_sha256) exit(0, "There is no host key associated with the SSH service on port "+port+".");

# check and report: try MD5 fingerprint first, if that fails look for sha256 fingerprint
res = check_ssh_fingerprint(fingerprint:fingerprint_md5, type: 'md5');
fingerprint = fingerprint_md5;
fingerprint_type = "MD5";
if(empty_or_null(res))
{
  res = check_ssh_fingerprint(fingerprint:fingerprint_sha256, type:'sha256');
  fingerprint = fingerprint_sha256;
  fingerprint_type = "SHA256";
}

if (!empty_or_null(res))
{
  report = '\n- SSH fingerprint      : ' + toupper(fingerprint) +
           '\n  SSH fingerprint type : ' + fingerprint_type  +
           '\n  Reference            : ' + res + '\n';
  security_report_v4(port:port,
                     severity:SECURITY_WARNING,
                     extra:report);
  exit(0);
}

audit(AUDIT_HOST_NOT, 'affected');
