#TRUSTED 1446317854d3fef5120b1bb4b22380639c0f40f9570f82a3a5847e1eae8322b4ef7d59d63639d342a608af9996669bd08590a213ac45a7751a7d1154459d9bf9768900ffa73954fac2bf3ea96449bacab7cd6cc2cabdf83fa5d50439dee01783152dd730534b0c2385c95e5d96b586e04bf1bee28b709a3bddb2d26aded2a71555cd0e0db9b56677d82174b43f70def057764623f88c481b60e40d35eaa194eafce32b2677ce66f44803569f61616d2d0bf328fa3159c933c8b56a6592d401827a029106784b58707c32bbc0e2916a7f7249c871093676de5373cdd9e4e89d801a96d4c6482330cd9fc0a58c83cb83cd221fc773ed249a3592bdb5cc5ee0b91dea7c8625fe19e9467a3f56f9e9e9e8e6a6bdbf823da28dd0b58da43b898293a7dd9fe71b437d6a2d8857b878516f119193a92a8af6b9c750b94112a13081222f7f8789f0aeae3fd7d461eff4055755508ae937e41007ebb963e4164c1ab3504c883890bc4d4b55dc37b9e4116e633aaffe2b87c5da9e1948f21274e14ebbaed5a2e826a13d711473761ec24a70b5f8f09126eded8162f12cbf61f1348d20358fe7e5f9cbceccd80954defefb52ea51de2bfd422eb9691cd6e9ef0298e7c3215250c8a834817a0d1dedf8e2a15db189202f7f1f8c3fc0ba87dffe00aecd34950b361c443866141f03de798c868272a18ef242842257b006ed3305c87968550af6
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133801);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2017-14491");
  script_bugtraq_id(101085);

  script_name(english:"Arista Networks EOS DNS 2 byte heap based overflow RCE (SA0030)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by a heap-based buffer overflow in dnsmasq.
This vulnerability allows a remote, unauthenticated attacker to run arbitrary code, create a denial of service (DoS) or
an out of memory situation.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/3577-security-advisory-30
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ceb5dd8");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Arista Networks EOS version 4.19.0F / 4.17.8M / 4.16.13M  or later. Alternatively, apply the patch or recommended mitigation
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14491");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:arista:eos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("arista_eos_detect.nbin");
  script_require_keys("Host/Arista-EOS/Version", "Settings/ParanoidReport");

  exit(0);
}


include('arista_eos_func.inc');
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit('Host/Arista-EOS/Version');
ext='2.77/6375386.erahndnsmasqUpstreamFixesHotfix0.5';
sha='90329906ff83272bb90907d14c7a72b107e3971b15b6263244ee8d49757277505d637ee794b4a98a6b73d6b85b653a4ee36182690b00ee29b07adf91182e76bd';

if(eos_extension_installed(ext:ext, sha:sha))
  exit(0, 'The Arista device is not vulnerable, as a relevant hotfix has been installed.');

vmatrix = make_array();
vmatrix['all'] =  make_list('0.0<=4.14.99');
vmatrix['F'] =    make_list('4.15.0',
                            '4.15.1',
                            '4.15.2',
                            '4.15.2.1',
                            '4.15.3',
                            '4.15.4',
                            '4.15.4.1',
                            '4.15.4.2',
                            '4.17.0',
                            '4.17.1',
                            '4.17.1.1',
                            '4.17.1.4',
                            '4.17.2',
                            '4.17.2.1',
                            '4.17.3',
                            '4.18.0',
                            '4.18.1',
                            '4.18.1.1',
                            '4.18.2',
                            '4.18.2.1',
                            '4.18.3',
                            '4.18.3.1',
                            '4.18.4',
                            '4.18.4.1',
                            '4.18.4.2');

vmatrix['M'] =    make_list('4.15.5',
                            '4.15.5.1',
                            '4.15.6',
                            '4.15.6.1',
                            '4.15.7',
                            '4.15.8',
                            '4.15.9',
                            '4.15.10',
                            '4.16.6',
                            '4.16.7',
                            '4.16.8',
                            '4.16.9',
                            '4.16.10',
                            '4.16.11',
                            '4.16.12',
                            '4.17.4',
                            '4.17.5',
                            '4.17.5.1',
                            '4.17.6',
                            '4.17.7');

vmatrix['misc'] = make_list('4.15.0FX',
                            '4.15.0FX.1',
                            '4.15.0FXA',
                            '4.15.0FXA.1',
                            '4.15.0FX1',
                            '4.15.0FX1.1',
                            '4.15.1FXB',
                            '4.15.1FXB.1',
                            '4.15.1FX-7060X',
                            '4.15.1FX-7060X.1',
                            '4.15.1FX-7260QX',
                            '4.15.3FX-7050X-72Q',
                            '4.15.3FX-7060X.1',
                            '4.15.3FX-7060X.2',
                            '4.15.3FX-7500E3',
                            '4.15.3FX-7500E3.3',
                            '4.15.4FX-7500E3',
                            '4.15.5FX-7500R',
                            '4.15.5FX-7500R-bgpscale',
                            '4.15.5FX-7500R-bgpscale.1',
                            '4.15.5FX-7500R-bgpscale.2',
                            '4.16.6FX-7500R',
                            '4.16.6FX-7500R.1',
                            '4.16.6FX-7500R-bgpscale',
                            '4.16.6FX-7512R',
                            '4.16.6FX-7060X',
                            '4.16.6FX-7050X2',
                            '4.16.6FX-7050X2.2',
                            '4.16.7FX-7500R',
                            '4.16.7FX-7500R-bgpscale',
                            '4.16.7FX-7500R-bgpscale.1',
                            '4.16.7FX-7060X',
                            '4.16.7FX-7060X.1',
                            '4.16.7M-L2EVPN',
                            '4.16.7FX-MLAGISSU-TWO-STEP',
                            '4.16.7.1FX-ECMP-FIX',
                            '4.16.8FX-7500R',
                            '4.16.8FX-7060X',
                            '4.16.8FX-MLAGISSU-TWO-STEP',
                            '4.16.9FX-7500R',
                            '4.16.9FX-7060X',
                            '4.16.9-FXB',
                            '4.16.10FX-7060X',
                            '4.17.1FX-VRRP6LL',
                            '4.17.1.1FX-MDP',
                            '4.17.2FX-OpenStack',
                            '4.17.3FX-7500R',
                            '4.17.3FX-7500R.1',
                            '4.18.1FX-7060X.2-SSU',
                            '4.18.1FX-7060X.1-SSU',
                            '4.18.1FX-7060X-SSU',
                            '4.18.2-REV2-FX.1',
                            '4.18.2-REV2-FX');
vmatrix['fix'] = 'Apply one of the vendor supplied patches or mitigation or upgrade to EOS 4.19.0F / 4.17.8M / 4.16.13M or later';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
else audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
