#TRUSTED 30261962c27d3c1c30c708fd51acd40c11630e57d9e7fbb2ec5e4ea7706281072c1923b92270da2b695b99a6b0982c3cfad016f5fc65dfeb0d8e7d0bfd104583bf4529ecf3709c68b63f3c539e61a80ba5dfba7011ff7e8c609980df191e19c862590158f5dbd7ec4d1f2574609bc3a56f923c60f475c2eabadaa8db567559ec2a230c0950d6567768d86c35e383ddab3518db4df5854cd71e0a91def5c60814e2e4a27cf8c6431416ce1968e21b97ae0cb01e6156d94da72cc062c01ffb3923d0f17e344c473cc9fe0e887fa6071809a1694be695ca6e829ce4cbf4ab4607f72bd213eeaa8e46cd433e2987b02c1a6a7ea353927018a9cc25b12bbbc1b29525e2847afb574f3b6d61a9bf575bebea444197559d1eafe430b140381fc5c092d0ac6954ef835b8b737dd619732f73f7193c99a1ed1dd4822aa956f04b3cf0e84f6c6cfe045faa0e58222f2a74c12abfa4b8b5912591b722f17a99e2838f18a43009c34b44c3e7b3b97bf35074fb95824b19404b78d2b7df513009386c8f110561b6bd8b92a0fc5ca77ba87e6a37ffb4f3f648b2371e5d047e8f2081cadc4d8b0ecf9ace6b21362b22fbc28e180bc33293412b8d80dd658cf0a9307b176e4d465586384c7fd1b72b84faad3eaf3b9332df72be5a618e4d7ca1c12fbb57430169f9a8bf8c62ee0ba71cdb849b15f7cce93e6b24b83d809336150f78fe57d0dda0b9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107067);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2016-2178", "CVE-2016-2183", "CVE-2016-6304");
  script_bugtraq_id(91081, 92630, 93150);

  script_name(english:"Arista Networks EOS 4.17 Multiple Vulnerabilities (SA0024) (SWEET32)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by multiple vulnerabilities in the included OpenSSL library :

  - An information disclosure vulnerability exists in the
    dsa_sign_setup() function in dsa_ossl.c due to a failure
    to properly ensure the use of constant-time operations.
    An unauthenticated, remote attacker can exploit this,
    via a timing side-channel attack, to disclose DSA key
    information. (CVE-2016-2178)

  - A vulnerability exists, known as SWEET32, in the 3DES
    and Blowfish algorithms due to the use of weak 64-bit
    block ciphers by default. A man-in-the-middle attacker
    who has sufficient resources can exploit this
    vulnerability, via a 'birthday' attack, to detect a
    collision that leaks the XOR between the fixed secret
    and a known plaintext, allowing the disclosure of the
    secret text, such as secure HTTPS cookies, and possibly
    resulting in the hijacking of an authenticated session.
    (CVE-2016-2183)

  - A flaw exists in the ssl_parse_clienthello_tlsext()
    function in t1_lib.c due to improper handling of overly
    large OCSP Status Request extensions from clients. An
    unauthenticated, remote attacker can exploit this, via
    large OCSP Status Request extensions, to exhaust memory
    resources, resulting in a denial of service condition.
    (CVE-2016-6304)");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/1749-security-advisory-24
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0310cb92");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fixed version. Alternatively, apply the
recommended mitigations referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2183");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version");

  exit(0);
}


include("arista_eos_func.inc");

version = get_kb_item_or_exit("Host/Arista-EOS/Version");

vmatrix = make_array();
vmatrix["F"] =    make_list("4.17.0<=4.17.1.1");
vmatrix["misc"] = make_list("4.17.1FX-VRRP6LL");

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
