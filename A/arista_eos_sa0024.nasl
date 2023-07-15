#TRUSTED 9335df6adc323f095a8e0c5fcfef0ff4be8608f33bbfd7209227fef584817014f0cca85ab229fba95d88ee29165fc170a0501da133164cbc84576efd06fb708d148eaedfdd3b1d8f110affe53eca9323c1f433b6d09a4427661b4ea70156d405c5a76daa793d91e767ddbddb4ed155572f94d3fe31a047aa8dc302090394af8dbdfa1f41c89891a4905438fafbfa068765c52bc642d44bfd323e655522cba47b7135e1d3169e8d1bbec631174c5ef6a6c3f45c5d1900e473855b4c75e34b0ac36a42d4e4ee993a0d452341feada773c80f225005cea0a533bc5384e07077b4dfb100c900745ccbcd54d3f7d03b605ee1d7633831db8ebb1c057e13947a87c4e1be03ec279e8df1d7e21af70f2f007b4c1179c3804a11762a8d2f4bda12c6327bf1f5b751655cce3e020401c67a46680f05912d7db10c35b22e2a29d8b834030e4257f1fdc305e6b4afe7415d46059ab2d834c4604e20959e6d4814d1f36d18d07ccfff12f87e91c068afffa28ac4998cc07aa93bc5d13f0dee907a09fafba13fb4024b7b0bd6f67ed0b541e0971c044799bde4e0b362edea6f14f36e84db9311ece9f34e0bbff367e0b70c8378f2bbc89d70b40ee90dd2198d458b0e14e190764499ec3148807a01f7c8978297fe6f77b7dc763b9773e213b63d66a2061e8c5d11d11464e948bca24a765b81516b6c2e3f00e6bb0b3e603098e0580a55b728a4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107066);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2016-2178", "CVE-2016-2183");
  script_bugtraq_id(91081, 92630);

  script_name(english:"Arista Networks EOS Multiple Vulnerabilities (SA0024) (SWEET32)");
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
    (CVE-2016-2183)");
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
vmatrix["all"] =  make_list("4.10.1<=4.13.99");
vmatrix["F"] =    make_list("4.14.0<=4.14.5",
                            "4.15.0<=4.15.4.1",
                            "4.17.0<=4.17.1.1");
vmatrix["M"] =    make_list("4.14.5<=4.14.12",
                            "4.15.5<=4.15.8",
                            "4.16.6<=4.16.8");

vmatrix["misc"] = make_list("4.14.5FX",
                            "4.14.5FX.1",
                            "4.14.5FX.2",
                            "4.14.5FX.3",
                            "4.14.5FX.4",
                            "4.14.5.1F-SSU",
                            "4.15.0FX",
                            "4.15.0FXA",
                            "4.15.0FX1",
                            "4.15.1FXB.1",
                            "4.15.1FXB",
                            "4.15.1FX-7060X",
                            "4.15.1FX-7260QX",
                            "4.15.3FX-7050X-72Q",
                            "4.15.3FX-7060X.1",
                            "4.15.3FX-7500E3",
                            "4.15.3FX-7500E3.3",
                            "4.15.4FX-7500E3",
                            "4.15.5FX-7500R",
                            "4.15.5FX-7500R-bgpscale.2",
                            "4.16.6FX-7512R",
                            "4.16.6FX-7500R.1",
                            "4.16.6FX-7500R-bgpscale",
                            "4.16.6FX-7500R",
                            "4.16.6FX-7060X",
                            "4.16.6FX-7050X2.2",
                            "4.16.6FX-7050X2",
                            "4.16.7M-L2EVPN",
                            "4.16.7FX-MLAGISSU-TWO-STEP",
                            "4.16.7FX-7500R",
                            "4.16.7FX-760X",
                            "4.16.8FX-MLAGISSU-TWO-STEP",
                            "4.16.8FX-7500R",
                            "4.16.8FX-7060X"
                            );

if (eos_is_affected(vmatrix:vmatrix, version:version))
{
  security_report_v4(severity:SECURITY_WARNING, port:0, extra:eos_report_get());
}
else audit(AUDIT_INST_VER_NOT_VULN, "Arista Networks EOS", version);
