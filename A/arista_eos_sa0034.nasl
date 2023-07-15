#TRUSTED 28d8bf50de4500910333209ba977ad75d5c33755ec911893eebae57d9c56009ad60ec732871ea04ccf50de7ff576b5a88eb8bafa628917f69255bc9613324c09114cb8a62a482c41064b689aa61ba0ef01d41685390956c8bd3003fe84d893e479fb909670bfb3b119047ba39c0527984bd280398a7f02a21dadee033fa9dc6f8258e116203e3cf5046566e871d9c21c9887f7d371f861a3556830cb165be41ec544d34e04bd0bb61972a4a2fb51b518ff6f403fff50f08aa3b452fcccc24342116afe9958eb340024c362609aaa11bd53ea2aceb75436c192ad284fa9042185df8c962258504c14c8fa6d5110f6ce9ebb5fb17d913c1edb926d098694ae2a21828befea9cb5b844e504c0c97ba34d1feb3524939dd51f003330fa1a310209353fcf43c3e84b1df162046119e11a53e3aa64ec676756272efb2da81cade700e8cdc7772a11af6854b7f441ee48e8d5c9c10b7c8ecda4c61cb985c123294184e7070f0cdeeb9d441aa4fc05c7039bc0b7f84baa31e1d44c0006a3c2ec94715f1328e63ebb62376d6e0f8b0ea702d43d605549b6997ef5fba24f175a3749aea682723e89c42278047fe8d08b88024dba12924349122059ef9d4e90e2810c8d39eaae07353455c5ed7766e281ad2494f9031244a0153f17044bc4b1be9aefde0af0aaf8d305c9d3edf8bd5b4dc979d33da003a1f5eaa5d0a9833a33583addf4796e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133865);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/25");

  script_cve_id("CVE-2017-18017");
  script_bugtraq_id(102367);

  script_name(english:"Arista Networks tcpmss_mangle_packet DoS (SA0034)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Arista Networks EOS running on the remote device is affected by a denial of service (DoS) vulnerability.
The tcpmss_mangle_packet function in net/netfilter/xt_TCPMSS.c in the Linux kernel allows a remote, unauthenticated
attacker to cause a DoS (use-after-free and memory corruption) or possibly have unspecified other impacts by leveraging
the presence of xt_TCPMSS in an iptables action.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.arista.com/en/support/advisories-notices/security-advisories/4577-security-advisory-34
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c9d929a0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an Arista Networks EOS version later than 4.20.1FX-Virtual-Router. Alternatively, apply the patch or
recommended mitigation referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/24");

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
include('audit.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit('Host/Arista-EOS/Version');

ext='SecurityAdvisory0034Hotfix.rpm 1.0.0/1.fc18';
sha='b708536d77702846079690786c50a65dcaaf39a24f56686bd6e4a90c38483b3e6141ef706ca1b581d0c4438b14f0304dcc366d4cdb5204005b1692ea4a28d2a9';

if(eos_extension_installed(ext:ext, sha:sha))
  exit(0, 'The Arista device is not vulnerable, as a relevant hotfix has been installed.');

vmatrix = make_array();
vmatrix['misc'] = make_list('4.20.1FX-Virtual-Router');
vmatrix['fix'] = 'Apply the vendor supplied patch or mitigation or upgrade to a version later than 4.20.1FX-Virtual-Router';

if (eos_is_affected(vmatrix:vmatrix, version:version))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:eos_report_get());
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Arista Networks EOS', version);
