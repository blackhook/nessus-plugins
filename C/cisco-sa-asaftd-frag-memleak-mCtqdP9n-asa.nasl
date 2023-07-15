#TRUSTED 0f5242538f73f292740f98686c8f34ddf038719d50c85a702a2ba511a142ef178bd99791bfc4b00aaaa9396feea87c8fbe857af708b93f66093ac2e3f96a2a6340bd837accdb5e06b9d43ef267cbb9183550ea01d94b99346908b5b49274564b88b86cfe9b4a260cc101bcb6f8fd1da148676e4646bdc11edd194668f0a35a8d52d54e00c609f0f8a5f6940df5d6c88f79e12376c261ac41e102297f0bb17e3a3a4e96b413072a96788de7060608118ce58a33bd759abf6fac36dbe46b5f0e9a38ff6fec86f3f9fa0a1f89636cddd2350da6bc57620dfed699da62af0bc513b7d9d614331e5114c0945768f7bd0b47f949036cf5fddc332217cb6a889002dca52b512c16c4c4edac73e131ec4ae8a40bd457ff02dcb3b5bbec3fc08aa2c586eef44a5566fd7822d160c521d4b25cd98d442c9ad8ee0aa83c0a01bc59110cad6dade77d396047d1232e057fc2877479f00f1f7868b0c29f1deafdae63c3547e2b68cd2eeb31b117fe6c945b8f9b51f44dc384d8645a080a8289418375009ccd80003d2451fd32fd027a5654ab1ec91bad988cc75db395095feae142d1a8e2a741d443000fbe6d69516e3b000b9c9c8eb621ae49cece374fbd93185eac830f75aade0ccd40bd1b704f3530b7e9b4097cf0fcbe49d31eaa4df8e8bbb8eb4af5ade066ac3f3f1262dba9f1b30bc620e26a573f1f84a672a84ab092cc1279def62486
#TRUST-RSA-SHA256 4554e8b2c72495c1084658bae47f1db124856c4f117b8e979c13a093398f09e8b3e7f56d211097859163e18197c91ff91429873de6e512e529153cea220db20f98ad849ad8e0d3222879f6209e543ab63047dfa4cf1c44f61a1c437383eb6997ff372a22755dee7b7616e155192858e7862a0adca0844307e3e9d14adf4e15566782cb449a1bab0487241e4ff121a4115ee760638296bb53c184aa4bdb1b3b2147854415f59821b5c12e99ebf5e22e0ecbad072567a8b4b5c8cc7afefda4589acbb3587068d34213d98e2d4fe945447380d076c79f519361b5aeb481aa6175cae11bd46f1cce2f26f8496f6fdb12a6e42d39f240baa9d4fbea37051a633a946bff687818ff048deb1b93fa495cea7975a8c3062c877e65ad1def455c13dac519b9720a4ac9694945f117d12493ae4e3c89aa9a215c0ec16bd92c7f762723454fefb4de3aa23a26161855d149a8d00003b13a052c994b18828961b60565040fc7d5e7672cbf0a97f02246e18d9aacd52d495f33a5e0b2d1cb567b0cf069cd6c4afed4a1129a80bcf5a7af7930242f9ecd60ef26bb8a6f052bccdcbddd36df84ac0532b9a65920bed0810fc94bd13bd3e90643fdd3854ddfe1350f887a3bb203f038d0fe545edcc56ccb57e9ea0b624a6e41e3895fbb2f3d6189b7d07a2d9cc9de52d13f13b6b3c4d6f911612bbc3e8ccb2000ad2baf009842491bb16ffc7399e1
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149851);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/31");

  script_cve_id("CVE-2020-3373");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu47925");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-frag-memleak-mCtqdP9n");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Adaptive Security Appliance Software IP Fragment Memory Leak (cisco-sa-asaftd-frag-memleak-mCtqdP9n)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance Software is affected by a vulnerability in
the IP fragment-handling implementation. This allows an unauthenticated, remote attacker to cause a memory leak on an
affected device. This memory leak could prevent traffic from being processed through the device, resulting in a denial
of service (DoS) condition. The vulnerability is due to improper error handling when specific failures occur during IP
fragment reassembly. An attacker could exploit this vulnerability by sending crafted, fragmented IP traffic to a
targeted device. A successful exploit could allow the attacker to continuously consume memory on the affected device and
eventually impact traffic, resulting in a DoS condition. The device could require a manual reboot to recover from the
DoS condition. Note: This vulnerability applies to both IP Version 4 (IPv4) and IP Version 6 (IPv6) traffic.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-frag-memleak-mCtqdP9n
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9d5e6d6");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74302");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu47925");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu47925");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3373");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}
include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var version_list = make_list(
  '9.8.4.22',
  '9.8.4.25',
  '9.12.4.2',
  '9.12.4.3',
  '9.13.1.12',
  '9.14.1.15'
);

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu47925',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list
);
