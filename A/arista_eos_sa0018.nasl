#TRUSTED b06c9df901472152e13d51b6c24d58cca67151bc79fa95124d4ae2cc8e3c02ac25f22d267b2dea3113d8b8bf175a685e5fd7bff8a33edf9fa54d1e03b93f1e390888dfe924c645657a22ebdd126e3dc9eab6bdcb2c90bce796ba768f8168c3c6b6e653e45eb6d0557acc0b2af3f0056779a88820fb4eb23b04169d12d82c52edb13c598454d498b7c6b2fa569cf0931535f041d8fbdb3d2d7eda3ea163f3d61a76e12c9e0a9e5a21556315b9ba45b27504e1c869161ac87fad5b4a660d5cb6d540d14fdb63173dc345f81b51432fffdd5867bec4461001820aa992f71fd43a28a97ccfd421da1ff5f945858c3bf7dc10cc3575cfe103c848efda9c2db20d353f468e6bae0dff80363204641498d4389b1df1b693682ab67e9a27697cc3777d3ec686dfd37ad6f4dd7db47865116dc871a3485ac13fcfc44a3872fc2d33749b93379876d6e7bf49cb963994d7c1ac59826dd7a0bc2e7b42805e934b77b5e3076501f01b25cf3bbe84d1921dcbdfab9096ff9704fca44738d3ed95cdee92ef15aa4d388eba20df6f0b65d28fc756905ead58662e00ae19fc5ffd0296d8291bfe525b21d093243dbb52d748cb76bb5c894b6216bd3592a0896629f92a2fc5b80c18d246733aa52e18d204932abed9ab83afb3ac88540dabe4b8e7bba982fe2e3d3bc7a6a06fadb81bb38b59b2ac172b546021fac90dda5fe1f79dd7a90ba3e96ce3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107060);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2015-3197", "CVE-2016-0703", "CVE-2016-0800");
  script_bugtraq_id(82237, 83733, 83743);
  script_xref(name:"CERT", value:"257823");
  script_xref(name:"CERT", value:"583776");

  script_name(english:"Arista Networks EOS Multiple Vulnerabilities (SA0018) (DROWN)");
  script_summary(english:"Checks the Arista Networks EOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is
affected by multiple vulnerabilities in the included OpenSSL library :

  - A cipher algorithm downgrade vulnerability exists due to
    a flaw that is triggered when handling cipher
    negotiation. A remote attacker can exploit this to
    negotiate SSLv2 ciphers and complete SSLv2 handshakes
    even if all SSLv2 ciphers have been disabled on the
    server. Note that this vulnerability only exists if the
    SSL_OP_NO_SSLv2 option has not been disabled.
    (CVE-2015-3197)

  - A flaw exists in the SSLv2 implementation,
    specifically in the get_client_master_key() function
    within file s2_srvr.c, due to accepting a nonzero
    CLIENT-MASTER-KEY CLEAR-KEY-LENGTH value for an
    arbitrary cipher. A man-in-the-middle attacker can
    exploit this to determine the MASTER-KEY value and
    decrypt TLS ciphertext by leveraging a Bleichenbacher
    RSA padding oracle. (CVE-2016-0703)

  - A flaw exists that allows a cross-protocol
    Bleichenbacher padding oracle attack known as DROWN
    (Decrypting RSA with Obsolete and Weakened eNcryption).
    This vulnerability exists due to a flaw in the Secure
    Sockets Layer Version 2 (SSLv2) implementation, and it
    allows captured TLS traffic to be decrypted. A
    man-in-the-middle attacker can exploit this to decrypt
    the TSL connection by utilizing previously captured
    traffic and weak cryptography along with a series of
    specially crafted connections to an SSLv2 server that
    uses the same private key. (CVE-2016-0800)

Note that these issues occur only when CloudVision eXchange (CVX) is
deployed as a virtual appliance and runs an EOS image. Therefore, only
CVX features leveraging SSLv2 in the EOS releases are vulnerable.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/1260-security-advisory-18
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4b2cf3");
  script_set_attribute(attribute:"see_also", value:"https://www.drownattack.com/drown-attack-paper.pdf");
  script_set_attribute(attribute:"see_also", value:"https://drownattack.com/");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20160301.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.15.5M. Alternatively, apply
the recommended mitigations referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/07");
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
vmatrix["misc"] = make_list("4.15.0F",
                            "4.15.0FX",
                            "4.15.0FXA",
                            "4.15.0FX1",
                            "4.15.1F",
                            "4.15.1FXB.1",
                            "4.15.1FXB",
                            "4.15.1FX-7060X",
                            "4.15.1FX-7260QX",
                            "4.15.2F",
                            "4.15.3F",
                            "4.15.3FX-7050X-72Q",
                            "4.15.3FX-7060X.1",
                            "4.15.3FX-7500E3",
                            "4.15.3FX-7500E3.3",
                            "4.15.4F",
                            "4.15.4FX-7500E3");
vmatrix["fix"] = "4.15.5M";

is_cvx = get_cvx();
if(!is_cvx) audit(AUDIT_HOST_NOT, "running cloud vision exchange");

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
