#TRUSTED 8a21e280dbac8a6eda2fa51e33d4d9421b53373c6261ff02347a257564e7400efca7aadbec11df87c18c1efb959061de921072e72ecaf78a7c88f24482c77ed9787d4f1f67b963ecdae183388d3bdf157cc24dd105ad5ff81e538c2714a559e62d7b08ca98ab2dac5942b60b7f731ffd8ad753a111dbbc1d68e8cd4a06009eb8f442393f30988684fd43f82c226afd05bb9df85d2c89895730dce2bb8901f91c414ab9a93cb7d981723b57e66306a3d578d96cd94da2b156196ec9a6c5499e757c78ba9d8298d742eeefb934e4eb4f4fdfab0d16e73abaa6a36e85901e3eaa973e9714e0250f5d42d94831b606ca782c4a2180af9d9c4249521b0b27b7ec02904521bc9364a14ddbc4fe1a610e08e92f655e843fa57b18f5718a531084eb7157229d4cc66e674d6bb59b4ee6db6abcdad922c38f986a3a007038dcf0cb174529157009993eeff29b8f689c5b564465718ec10659b05b55d6ba54e46a49a5614e055fefe17a89e5b6ef96aac229ad72bb03b171b6796a3ce61bf1cba94cffd9da5ad87215236850be53bc8f197ff3ae4a8cea1db6ad79f150822e2834a68ce716b2b091c5443c116e8b65b668048c55093e8468767c11f4f22844b1b774e7ba752d6f6d84efe4670c0b345584f56568dce5a3612fd8cc2e6617a642b780660827e07c356041ba28f7a13e9cb11cb39efb2b9234858641883d1e95bb8ff13649f5
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102915);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-14115");
  script_bugtraq_id(100585);

  script_name(english:"Default Password '5SaP9I26' for 'remotessh' Account");

  script_set_attribute(attribute:"synopsis", value:
"An administrative account on the remote host uses a known default
password.");
  script_set_attribute(attribute:"description", value:
"The account 'remotessh' on the remote host has the default password '5SaP9I26'.
A remote attacker can exploit this issue to gain administrative access
to the affected system.");
  script_set_attribute(attribute:"see_also", value:"https://www.nomotion.net/blog/sharknatto/");
  script_set_attribute(attribute:"solution", value:
"Change the password for this account or disable it.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14115");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("ssh_lib.inc");

checking_default_account_dont_report = TRUE;

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (! thorough_tests && ! get_kb_item("Settings/test_all_accounts"))
 exit(0, "Neither thorough_tests nor 'Settings/test_all_accounts' is set.");

port = kb_ssh_transport();

session = new("sshlib::session");
session.open_connection(port:port);
ret = session.login(method:"password", extra:{"username":"remotessh", "password":"5SaP9I26"});
session.close_connection();

if(ret) 
{
  report="It was possible to login to the remote host using the default credentials of remotessh:5SaP9I26.";
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_HOST_NOT, "affected");
