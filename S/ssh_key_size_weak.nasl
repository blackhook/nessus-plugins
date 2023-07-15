#TRUSTED 709615b65ffa4c94c6549815c2ea16c5ce034ec8f3c0a6d93c88fb219035159418c0328249eb42efe7b5c1d8b38941798d20b220e04b6fdcc3f30490ce4d29baf7eb2f1c6c450d3e73411374e48aa651870f12eecaf4689d22343d6403e60d054da3d564f1a4e88e8ab59b1dc2e3b7fca82cb746fb7419cc86c2367ce3797be16f3fb19c0699d78bb91dc0dfe6b9d787b9dc1c887b9e0ba01313ba0700c9c90a00ce6c9c42a291e17093fa65894d49b7e324479a120bf1476677229630a6eb81a8c276c1c0abcab0f331a14c22b45d313610c57193b14ad068e9dedb67f90fa369085eadeae41b51e9e99b691459ea49f83337d83ab65f082792f8ec697f7a8b13c0bcdc86cfdd73f4f09b201273ee1fbee0ff920d30e72fd8d02dbf1e4258e7aad44c6eba7570fc5739d586a8a8b501c3e0f6e4b5ccad87db70030407d8703f24ae7305ecd5244d8a85b4ba62d5305b00c844da46ce33b52a58108508eec458a2a92cf09129dec359c97f748cbb816f00251e44cb15162afc4bfccd1123e46ea8fe0fd94f4251760db085287cc624a95cb6cf9e8b5e9036d27f91cce3be4bade5774099164b0e9cb5e516cef3ef11e9c1f6a66d10eaf84a39cf1bc4d8cb7b7d5784330d9a0dfb7b0b341722646cbaea0c87d5034ca392c92388186bcfdc926dc9989a119cfd4352f6395186480626bac3361ed96d47812fb7c458fa551e5c6c
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153954);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/13");

  script_name(english:"SSH Host Keys < 2048 Bits Considered Weak");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host has public key that is considered weak.");
  script_set_attribute(attribute:"description", value:
"The remote SSH server has a host key size that is smaller than 2048 bits. NIST Special Publication 800-57 Part 3
Recommendation for Key Management recommends RSA keys greater or equal to 2048 bits in length.");
  # https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57Pt3r1.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8c76607");
  script_set_attribute(attribute:"solution", value:
"Generate a new, larger SSH host key.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for weak host key");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


include('ssh_func.inc');

# used as a flag in the SSH libs
checking_default_account_dont_report = TRUE;

enable_ssh_wrappers();

if (supplied_logins_only)
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

var soc = open_sock_tcp(port);
if (!soc)
  audit(AUDIT_SOCK_FAIL, port);

var _ssh_socket = soc;

# Tell the server we support only RSA host keys, to ensure we get sent one.
sshlib::KEX_SUPPORTED_NAME_LISTS.server_host_key_algorithms = 'ssh-rsa';

ssh_login(login:'n3ssus', password:rand_str(length:8));
ssh_close_connection();

# KEY_LEN will be null if the SSH server does not support ssh-rsa
if (empty_or_null(KEY_LEN))
  audit(AUDIT_LISTEN_NOT_VULN, 'SSH server', port);

var report = 'The remote SSH server host key size is ' + KEY_LEN + ' bits.';

# audit out if we are not affected
if (KEY_LEN == 0 || KEY_LEN >= 2048)
  exit(0, report);

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
