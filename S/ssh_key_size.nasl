#TRUSTED 2e599c4b691d38f877cf2838f9b486d0b77372c34cf954e396a3c9b51df27e5279adb74b6e74b8f80d6edad44d0efb47ba987d18f983513aeb218cbc90530123a00ee3cf5240659374d476519d141b14b2208ab1f243ab30fe905631034cdd49927dd3810b489e8c44346f79aab9c1965c64fab4a34538bb78331217ad1fb5cfb7c93807aaa5e3a0bc538d7913a1837d6ac88cc8e8150f29cfb994ce8ed607d72c9beb45bd6b47fc890dce81f6b1093da2849cc638a236fa9c6e8c5026ac7a79589683762c3cd20709d5f19665668f2c5e98a8982f081b7894381992ccf88d1435a8c1bfbbbf401e373fc80173ace37b945be706c5c765fabe976c98998d68a1cfec74a9a6f566838167035a52fb691dd3145fa825cb5896be093d6027d0ea7d6292e8b4cb9ea504968ca27db431b8324384e09dde2b36d84a7a3b1a1948f3aa5a24bf18cbd9df1dab5d2b5c7ef6c26da846d1b23897419a1de11904318fe059c53dd3e0363afabfd97a3407a38a6e3a843984071e1097dcaecc0cc0f11368bc8bd0dbc8817c60f295ae86216980958837a8381056b8e0bf7d32c47e051ac3e1a2a485ab30feaebb7d21e74e03b899129382ed567fd8c3943555cbf9c6f0e0ba768218842270f69356ecb0bc7bd03baab0d0e7a9208728bd529bf6bdb3205799c5d3e1ccecd86ff202e2b69b10c2c30d77d99f521305493468d35e5d4a5e55f6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(57620);
 script_version("1.11");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

 script_name(english:"Small SSH RSA Key");
 script_summary(english:"Negotiate SSHd connections");

 script_set_attribute(attribute:"synopsis", value:
"The SSH server is running on the remote host has an overly small
public key.");
 script_set_attribute(attribute:"description", value:
"The remote SSH daemon has a small key size, which is insecure.  Given
current technology, it should be 1024 bits at a minimum.");
 script_set_attribute(attribute:"solution", value:"Generate a new, larger key for the service.");

 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"risk_factor", value:"High");

 script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2012-2020 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 script_exclude_keys("global_settings/supplied_logins_only");
 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

checking_default_account_dont_report = TRUE;

enable_ssh_wrappers();

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

_ssh_socket = soc;

# Tell the server we support only RSA host keys, to ensure we get sent one.
sshlib::KEX_SUPPORTED_NAME_LISTS.server_host_key_algorithms = "ssh-rsa";

ssh_login(login:"n3ssus", password:rand_str(length:8));
ssh_close_connection();

if ( KEY_LEN > 0 && KEY_LEN < 1024 )
  security_hole(port:port, extra:"The remote SSH RSA host key size is set to " + KEY_LEN + " bits.");
else if (!isnull(KEY_LEN))
  exit(0, "The remote SSH RSA host key size is set to " + KEY_LEN + " bits.");
else
  exit(1, "The remote SSH host doesn't support RSA host keys");
