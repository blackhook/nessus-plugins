#TRUSTED 8bf9b0ad1644878042b76698e5f8060e72be951f6a3f7ce423ac8aa77e2e46b1491ee7c9f31235cec6942e34d3bbf02795f8369149145e1bc4236a0741f9f9e8a2df7d4404445a2ede5cafb42d9cdb70b1b7e2fc0deceb0bf918ff7b5a28a273aad524165c0369a4b5d48ffd31c0ecf6a4bd06be27c87211ddc7d8123d5a4ef2a72f37d81f352fdd8b1be16595cc86b0e10dcae0ac033f6ed02927ba727ad0d21938f08a35d60be5cab20622b3e6939e016a7eb6493caf625bb645298ebd536c0fa6f486629945860d9cadd9366251161d40123329e8bb0b036cdb02dde6e2bd71da1dbfae91296db896afec38c1ffee1df37197ff94017a35b5f4ba8e7a8211daf425f2bae2b360e167bd3a2e0b99bbed173e584f39454f1ba654ef26761987992ebc63970a6cd9bac94f74e6aaef7ccb6f3de923e4e30dae8f208d06e571d3ca19394f8f6dae186303703e6fb0a6b64e509148a9ecf9a854751a68716f6715ca4d3db8d8e4b90781e34116cbe95b2620f881947376a038d0027e493897719babc564a26eb5137c743bf5335fac050926ed65488b8f9d67b982923fb74422b7747a4d30924fc904e84867e3128cdf77b9162fe9b8ef908cc6784cab937abbb463dd8ab510243065c0a3345855c958c1dd953428efedd2b2aa5af452dd5208c1455f01eaa16c90cb2e3a1b85587bbf9c8439491aecf7494511cfb896b5452693
#TRUST-RSA-SHA256 6238516e371288c56778c1cfa482af8ec4321063eb8b2bd9db97d2bbd757fd7b7c298b7339648e215dc8504ee4f91c0cde7c3062e865f950d2178532a9b867fe3b8f214c5163c508f6ecf62730a929d41589621aee5ae773da340c2f11b515b5f044a461f0439d69800ced434e6794775fd945d7c93c356d58ddcc27bca26f694e00dd43634ae8ce7f8c004d8aae988a07749b0ac595dff51504c72cb3ce1b6942f8426a4a3a163ca4ef99a366af2599da64901c463a66d09d30262c17aa004424287d8aca376dc27991c414bb8a0737af49c510f477227c6a2938d53d2efc2d2ec226120d39bd831e97aaab897f4a803e2698399c2afd10ba68c133a9539680ac24f44b2cc0f3d77e0d3125f1058d9692c70ad8d5df51902b1cbabd548a118f41aaa4f345485463f4aca12044a224c9202a9aa105a49be3c7ae3931293bed5d202508f0645e0b61abe5bfaeb7609654733d5c5360b840a0c88dd2e891346dfe819bca11e73fda9938c852d38f898dbe91b6dfcf5d4381711e04e9df6c9956227aa45ac44147d63a0cd275f6cbd3cd63095b73e095acbf4d039621c12335f3447abe78b4f42ba755856d6f3119aef5375fc2003abe90f5bc8fe2db62be3ba36f912db04f4cf2c6b50424e21f681cff9c74c22d8a25426fecc9f2f2611ab2da5db431e2a64486bd999d8e0893efbd96863f82052b28ea07f29debdbb56e2165d0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(86328);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2015-4000");
  script_bugtraq_id(74733);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SSH Diffie-Hellman Modulus <= 1024 Bits (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host allows SSH connections with one or more Diffie-Hellman
moduli less than or equal to 1024 bits.");
  script_set_attribute(attribute:"description", value:
"The remote SSH server allows connections with one or more
Diffie-Hellman moduli less than or equal to 1024 bits. Through
cryptanalysis, a third party can find the shared secret in a short
amount of time (depending on modulus size and attacker resources).
This allows an attacker to recover the plaintext or potentially
violate the integrity of connections.");
  script_set_attribute(attribute:"see_also", value:"https://weakdh.org/");
  script_set_attribute(attribute:"see_also", value:"https://stribika.github.io/2015/01/04/secure-secure-shell.html");
  script_set_attribute(attribute:"solution", value:
"Reconfigure the service to use a unique Diffie-Hellman moduli of 2048
bits or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"An in depth analysis by Tenable researchers revealed the Access Complexity to be high.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service.nasl");
  script_require_keys("Services/ssh", "Settings/ParanoidReport");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("audit.inc");


##
# Checks to see if the server can be forced to use a DH
# group exchange with a modulus smaller than or equal to
# 1024
#
# @param socket : socket of SSH sever
# @param port   : port for socket (used in exit messages)
#
# @remark exits with message when network failure occurs
#
# @return TRUE  if the server supports a GEX with 1024 mod
#         FALSE if the server does not allow this
##
function can_force_dh_gex_1024(socket, port)
{
  if(isnull(socket))
    socket = _FCT_ANON_ARGS[0];
  if(isnull(socket))
    return FALSE;

  local_var key_exchange_algo        = "diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1";
  local_var server_host_key_algo     = "ssh-rsa-cert-v01@openssh.com,ssh-dss-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-dss-cert-v00@openssh.com,ssh-rsa,ssh-dss";
  local_var enc_alg_client_to_server = "aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc";
  local_var mac_alg_client_to_server = "hmac-sha1";
  local_var cmp_alg_client_to_server = "none";
  local_var enc_alg_server_to_client = enc_alg_client_to_server;
  local_var mac_alg_server_to_client = mac_alg_client_to_server;
  local_var cmp_alg_server_to_client = cmp_alg_client_to_server;

  # Initialize key exchange
  local_var ccookie = "";
  while(strlen(ccookie) < 16)
    ccookie += raw_int8(rand()%256);
  local_var data =
    ccookie +                              # cookie
    putstring(key_exchange_algo) +         # kex_algorithms
    putstring(server_host_key_algo) +      # server_host_key_algorithms
    putstring(enc_alg_client_to_server) +  # encryption_algorithms_client_to_server
    putstring(enc_alg_server_to_client) +  # encryption_algorithms_server_to_client
    putstring(mac_alg_client_to_server) +  # mac_algorithms_client_to_server
    putstring(mac_alg_server_to_client) +  # mac_algorithms_server_to_client
    putstring(cmp_alg_client_to_server) +  # compression_algorithms_client_to_server
    putstring(cmp_alg_server_to_client) +  # compression_algorithms_server_to_client
    raw_int32(0) +                         # languages_client_to_server
    raw_int32(0) +                         # languages_server_to_client
    crap(data:raw_string(0x00), length:5); # payload
  sshlib::_compat_session.sshsend(data:data, code:sshlib::PROTO_SSH_MSG_KEXINIT);

  # Try to force 1024 bit modulus
  data =
    raw_int32(128)  + # min key length
    raw_int32(1024) + # preferred key length
    raw_int32(1024);  # max key length
  sshlib::_compat_session.sshsend(data:data, code:sshlib::PROTO_SSH_MSG_KEXDH_GEX_REQUEST);

  data = sshlib::_compat_session.sshrecv(length:1000);

  # Newer versions of OpenSSH appear to just not respond at all
  # if you have a maximum moduli value below their min moduli
  if(isnull(data))
    return FALSE;

  # Anything other than KEXDH_REPLY probably means the server sent us an error back
  if(ord(data[0]) != SSH_MSG_KEXDH_REPLY)
    return FALSE;

  data = sshlib::_compat_session.last_packet.payload;

  # Also shouldn't happen
  if(!data)
  {
    close(socket);
    exit(1, "The SSH server on port "+port+" did not respond as expected to the group exchange request.");
  }

  # Check the mod length
  local_var p = getstring(buffer:data, pos:0);
  if(strlen(p)-1 <= (1024 / 8))
    return TRUE;

  return FALSE;
}

port = get_kb_item_or_exit("Services/ssh"); # this will branch
sshlib::default_local_version = "OpenSSH_6.4";

# Only nation states might have the processing power to
# exploit this and nearly all SSH implementations will be
# flagged
if(report_paranoia < 2)
  audit(AUDIT_PARANOID);

# Server vulnerable if report is not blank
report = "";

# Negotiate connection
_ssh_socket = open_sock_tcp(port);
if(!_ssh_socket)
  audit(AUDIT_SOCK_FAIL, port);

# Exchange versions
server_ver = ssh_exchange_identification();
if(isnull(server_ver))
  audit(AUDIT_SERVICE_VER_FAIL, "SSH", port);
if("SSH-2.0" >!< server_ver && "SSH-1.99" >!< server_ver)
  audit(AUDIT_NOT_LISTEN, "SSH 2.0 Server", port);

# Check and make sure we got valid KEX INIT data
server_kex_dat = sshlib::_compat_session.sshrecv(length:2048);
if(isnull(server_kex_dat) || ord(server_kex_dat[0]) != SSH_MSG_KEXINIT)
{
  ssh_close_connection();
  exit(1, "The SSH server on port "+port+" did not send key exchange data.");
}

# Check key exchange for weaknesses
if("diffie-hellman-group1-sha1" >< server_kex_dat)
{
  group1_supported = TRUE;
  report += 
    '  It supports diffie-hellman-group1-sha1 key\n' +
    '  exchange.\n\n';
}
if("diffie-hellman-group-exchange-sha1" >< server_kex_dat && can_force_dh_gex_1024(_ssh_socket,port:port))
{
  gex1024_supported = TRUE;
  report += 
    '  It supports diffie-hellman-group-exchange-sha1\n' +
    '  key exchange and allows a moduli smaller than\n' +
    '  or equal to 1024.\n\n';
}
ssh_close_connection();;

if(report != "")
{
  if (get_kb_item("Settings/PCI_DSS"))
  {
    # Used by pci_weak_dh_under_2048.nasl
    set_kb_item(name:"PCI/weak_dh_ssh", value:port);
    pci_key = "PCI/weak_dh_ssh/moduli/" + port;
    if (group1_supported && gex1024_supported)
    {
      replace_kb_item(name:pci_key, value:"both");
    }
    # Only one of the two is supported
    else
    {
      if (group1_supported)
        replace_kb_item(name:pci_key, value:"group1");
      if (gex1024_supported)
        replace_kb_item(name:pci_key, value:"gex1024");
    }
  }

  if(report_verbosity > 0)
  {
    # This is a hard attack ... for now.
    report =
    'The SSH server is vulnerable to the Logjam attack because :\n\n' +
    report +
    'Note that only an attacker with nation-state level resources\n' +
    'can effectively make use of the vulnerability, and only\n' +
    'against sessions where the vulnerable key exchange\n' +
    'algorithms are used.\n';
    security_note(port:port,extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "SSH Server", port);
