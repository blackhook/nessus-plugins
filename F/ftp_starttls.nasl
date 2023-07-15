#TRUSTED 9aed0c4a14584f1d8adbc05f740b527b8d631770365e81871cebca239ef0eca1593bfbea8d6d5d92f245913e15f019832a07ce77227cb03f060bdd64abf00cb81dcd471beb3fbcf31469c6b5fb1b622b195c8f16dd952bbf7e06d9cd81677c183ffaa925874861d954914df5e47c892d673af83268b40a2f2078c4efb41675630b17db385e820dfddef3a124aaa6c00099b76817473556fbe2cc69ba4ad6538b9a99d021b72dc8b751961455640dc6bd25fe0b5173972883435bd97d03eb503a660c0a89336a9b722dd5d38f06370ca019d14c8de04d90f569f87a3b377718958f1fa08bd4182c4ea9e1f42fc716eb1e1b423a9db34bfe2ab236952bc8014b2c83f200e4ddea8552ce773334716401d0d9a1728844d232e7a287a07016c8343b3dda3bd0510890ee13881e293cc15beac88118bbc9eb31142fcf6addd22f509e7e37030997bb101a0ef6553be0f04ed53f2ea4786202efec9b3bcd33a051f065632fbaa400949a05171ef4c647f1102e7d32dd68953d25b3c1471e5324ecb52955575dc68c62a52c7a414b0c559fd36d79948083d6339e7a0c99b1b14d3f5af92472809be798c14ce3cbb4b02cb5c0d91314071736d70afe1188fc8bb4a476a9980eba50269394a89179948f6f0f9d8685816f09b50ff6a639e9fe5a63b6f8a95ed8a8658d165e6b8e3cc08e0a3d5df35eaeee932c66419f7d2748579adec018
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42149);
  script_version("1.15");

  script_name(english:"FTP Service AUTH TLS Command Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(attribute:"synopsis", value:
"The remote directory service supports encrypting traffic.");
  script_set_attribute(attribute:"description",  value:
"The remote FTP service supports the use of the 'AUTH TLS' command to
switch from a cleartext to an encrypted communications channel.");
  script_set_attribute(attribute:"see_also", value:
"https://en.wikipedia.org/wiki/STARTTLS");
  script_set_attribute(attribute:"see_also", value:
"https://tools.ietf.org/html/rfc4217");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/11");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english: "This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_exclude_keys("global_settings/disable_test_ssl_based_services");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("ftp_func.inc");
include("x509_func.inc");

if (get_kb_item("global_settings/disable_test_ssl_based_services"))
  exit(1, "Not testing SSL based services per user config.");

var port = get_ftp_port(default:21);

var encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The FTP server on port "+port+" always encrypts traffic.");


var soc = open_sock_tcp(port, transport:ENCAPS_IP);
if (!soc) exit(1, "Can't open socket on port "+port+".");
ftp_debug(str:"custom");

var s = ftp_recv_line(socket:soc);
if (!strlen(s))
{
  close(soc);
  exit(1, "Failed to receive a banner from the FTP server on port "+port+".");
}


var c = "AUTH TLS";
var s = ftp_send_cmd(socket:soc, cmd:c);
if (strlen(s) < 4) 
{
  ftp_close(socket:soc);

  if (strlen(s)) var errmsg = ('The FTP server on port '+port+' sent an invalid response (' + s + ').');
  else errmsg = ('Failed to receive a response from the FTP server on port ' + port + '.');
  exit(1, errmsg);
}
var resp = substr(s, 0, 2);
replace_kb_item(name:"ftp/"+port+"/starttls_tested", value:TRUE);

if (resp && resp == "234")
{
  # nb: call get_server_cert() regardless of report_verbosity so
  #     the cert will be saved in the KB.
  var cert = get_server_cert(
    port     : port, 
    socket   : soc, 
    encoding : "der", 
    encaps   : ENCAPS_TLSv1
  );
  if (report_verbosity > 0)
  {
    var info = "";

    var cert = parse_der_cert(cert:cert);
    if (!isnull(cert)) info = dump_certificate(cert:cert);

    if (info)
    {
      var report = (
        '\n' +
        'Here is the FTP server\'s SSL certificate that Nessus was able to\n' +
        'collect after sending a \'AUTH TLS\' command :\n' +
        '\n' +
        crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n' +
        info +
        crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n'
      );
    }
    else
    {
      var report = (
        '\n' +
        'The remote FTP service responded to the \'AUTH TLS\' command with a\n' +
        '\'' + resp + '\' response code, suggesting that it supports that command.  However,\n' +
        'Nessus failed to negotiate a TLS connection or get the associated SSL\n' +
        'certificate, perhaps because of a network connectivity problem or the\n' +
        'service requires a peer certificate as part of the negotiation.'
      );
    }
    if (COMMAND_LINE) display(report);
    else security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
  }
  else security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

  replace_kb_item(name:"ftp/"+port+"/starttls", value:TRUE);

  # nb: we haven't actually completed the SSL handshake so just bail.
  close(soc);
  exit(0);
}
ftp_close(socket:soc);
