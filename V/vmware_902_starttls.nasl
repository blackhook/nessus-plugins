#TRUSTED 639f574cbd79b3a58533140b4573978bfdade7a7f2baaf35e401d4749e20e0e43b38bb8db873afa93631777ada016134a0e39dd8599bfdf2db8ae043e7b6d1ba5f72e9d63f00e65603db8481fd16c571601d9bdae3b8280b89c92ed753af95301cdd13287ad02e4aebf88f79681598b3b6dbff1743c8a9c509796d2ff877193a721a828be1e7881b6a7ca0cb0d29da539e6d355654e4b86b99404e6d6aa5b2e7bb31c40e4c933623c0aa179d8b1cfe2175d3f417e67bdb0023d9c365b1d8552066ed0ca7314ec668f99026df67bb812d36d2a08bea1813481509c89c23988b0cf3a9ee204ad490f50b7c19ace14fed4a90f33b22ff9ce73f7aa8a6d8c8bb3a035b10c8de8c5c50a95bc33c3e97c2180e1479e5bba192da508b6bcae31530abad3b536e07ff3ff291eb64efc221df0554f1790638c89aaac1b9fbf352972df1fa5f765877cfb598cfbf9e443448487614795cfe006b24038dbd25d52370dd052eb578a911c12dea3a799f8b6787cf20b0811334bb9131fda1929780a9a87e24b0a52e3c9b9b179e9ad6a47a365ab380e5fa97e04241993d66615628dce099755cb9e77afbdcc66aa2ec42df9a7885a4c99ab7a35dc4402e4de8b5e2e925720dbc7bf3f8a499bde0a00201e9cc2161246878b1e0c20faff3869598a9a96257cc6b6cf68919c5f6491407d84cd1b58f40abaaa956e001c650d2544fcec5c2ce923d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122534);
  script_version("1.4");

  script_name(english:"VMWare STARTTLS Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports encrypting traffic.");
  script_set_attribute(attribute:"description", value:
"The remote VMWare server supports the use of encryption
initiated during pre-login to switch from a cleartext to an
encrypted communications channel.");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_exclude_keys("global_settings/disable_test_ssl_based_services");
  script_require_ports(902);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");


##
# This function is used to retrieve the cert from a vmware 
# service running on port 902. The way the starttls connection
# works we have to use a custom function to retrieve the cert. 
# 
# @param [port:int] The port to retrieve the cert from 
# 
# @return list of certs or NULL on failure
##
function vmware_902_cert(port)
{
  local_var line, res, socket, hello, buf, done, msg_type, 
  msg_len, msg, hand_type, hand_len, hand, idx, n, i, banner,
  securerenegotiation, cert_len, fn, host, sni_kb;

  # Establish the connection and receive the ssl handshake response
  socket = open_sock_tcp(port, transport:ENCAPS_IP);
  if (!socket) return NULL;
  hello = client_hello(v2hello:FALSE, version:raw_string(0x03, 0x00), securerenegotiation:securerenegotiation);
  banner = recv(socket:socket, length:1024, timeout:10);  
  if (banner !~ "^220 VMware Authentication Daemon Version" && "SSL Required" >!< banner)
    return NULL;

  send(socket:socket, data:hello);
  buf = recv_ssl_recs(socket:socket, timeout:10);
  close(socket);
  
  # parse the certificate
  while (!done && strlen(buf) > 5)
  {
    msg_type = ord(buf[0]);
    msg_len = ord(buf[3])*256 + ord(buf[4]);
    # nb: msg_len doesn't include the first 5 bytes.
    msg = substr(buf, 0, msg_len+5-1);
    buf = substr(buf, msg_len+5);
    
    # Handshake message.
    if (msg_type == 22 && strlen(msg) > 3)
    {
      while (!done && strlen(msg) > 8)
      {
        hand_type = ord(msg[5]);
        hand_len = ord(msg[6])*65536 + ord(msg[7])*256 + ord(msg[8]);
        # nb: hand_len doesn't include the first 4 bytes.
        hand = substr(msg, 5, hand_len+4+5-1);

        # Certificate handshake.
        if (hand_type == 11 && strlen(hand) > 7)
        {
          idx = 7;
          n = 0;
          while ( idx < strlen(hand) )
          {
            # First cert belongs to the server itself.
            if ( idx + 3 > strlen(hand) ) break;
            cert_len = ord(hand[idx])*65536 + ord(hand[idx+1])*256 + ord(hand[idx+2]);
            cert[n++] = substr(hand, idx+3, cert_len+idx+3-1);
            idx += cert_len + 3;
          }
          ssl_dbg(src:fn, msg:'Received Server Certificate handshake.');
          done = 1;
        }
        msg = substr(msg, hand_len+4);
      }
    }
    else 
    {
      ssl_dbg(src:fn, msg:"Non-handshake message of type "+
      msg_type+" received from "+host+":"+port+"!");
      return NULL;
    }
  }

  if (done)
  {
    for ( i = 0 ; i < max_index(cert); i ++ )
    {
      cert[i] = blob_to_pem(cert[i]);
      ssl_dbg(src:fn, msg:"Successfully retrieved certificates on port "+port+", setting them in the KB.");
      if ( i == 0 ) replace_kb_item(name:"SSL/Certificate/" + sni_kb + port, value:cert[i]);
      else replace_kb_item(name:"SSL/Certificate/" + sni_kb + port + "/" + i, value:cert[i]);
    }
  }

  return cert;
}

###
### Main
###

if (get_kb_item("global_settings/disable_test_ssl_based_services"))
  exit(1, "Not testing SSL based services per user config.");

app = "VMWare";
port = 902;

# Find out if the port is open.
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Connect to the port.
soc = open_sock_tcp(port, transport:ENCAPS_IP);
if (!soc) audit(AUDIT_SVC_FAIL, app, port);

# Confirm the vmware startls connection
soc = vmware_902_starttls(encaps:ENCAPS_SSLv3, socket:soc);
if (!soc) exit(1, "The " + app + " instance on port " + port + " didn't accept our STARTTLS command.");
set_kb_item(name:"vmware902/" + port + "/starttls", value:TRUE);

# Clean up.
close(soc);

# Get the server certificate, we can not use get_server_cert here because
# of how the connection is established and how get_server_cert works
cert = vmware_902_cert(port:port);

# Report our findings.
report = NULL;
info = NULL;
if (report_verbosity > 0)
{
  cert = parse_der_cert(cert:pem_to_blob(cert[0]));
  if (!isnull(cert))
  {
    info = dump_certificate(cert:cert);
  }

  if (info)
  {
    snip = crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);

    report =
      '\nHere is the ' + app + "'s SSL certificate that Nessus" +
      '\nwas able to collect after sending a pre-login packet :' +
      '\n' +
      '\n' + snip +
      '\n' + info +
      '\n' + snip +
      '\n';
  }
  else
  {
    report =
      '\nThe remote service responded to the pre-login packet in a way that' +
      '\nsuggests that it supports encryption. However, Nessus failed to' +
      '\nnegotiate a TLS connection or get the associated SSL certificate,' +
      '\nperhaps because of a network connectivity problem or the service' +
      '\nrequires a peer certificate as part of the negotiation.' +
      '\n';
  }
}

security_note(port:port, extra:report);
