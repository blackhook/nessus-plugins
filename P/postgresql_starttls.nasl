#TRUSTED 3c76ebf633d994f3aa2f320bfbf6d696c54843218c5e9274fed6733761504b0435a210ccbc173c0d0ee71d3c4ca5f0f7d53fbca9d2c9c6f395c2b6c791633be0a2a43152364dde88618b8bf830ad0bd46ba37b3fc5dd30b1721054e8714fcda81445ac74b72a0ce2c5cddeffa1e7ec242347ab10e1a9d2dbda312081479137d746c1ce030a8a6a416df45e29e0d9da1c0334c2b6583136ee597796ce543698dc350c635b6ca3a788a9d3d8279bf2bc81ec8b78ac14b16ca8f6375a5e86839a64ddb70fb4286d5ee306266d8237a9040e32a9e2d01f1179fb8af7c2336099951b7acfb11333c5388b82c0b5c7808533acf786ce833e1a607c7755c993aa16206c24a0421ce5ceb8292131b9261c9f47f5a0959d49469157a854098a0df85bb70adc28c114cd9018a3d73a20fc8c5d72230bc2fa2c78a05fa868700aeb98545f853b9eef956e18580842e83e0e62f014e43d61d9a32cbd99a9eedd377fc3dd2b03ad632f0045ab79afa44ec479e07a7ffca1392529ccc0787172102aaac92d7b9cc2112583fed48a3465c70ae82401c03d6d30eaed5176958a5f7ace533ed075a8abb799e4ba5eada54d1b795f7718559cfde9991521a0520330e7cd84eb922e04fa0b001cf532806984d176266af5a0c9ca6f32b09fae2534777144fa7f683c16c483be865bc628dbbdddacc63903678a633b182511ee7e11b28b7cc3ea415e56
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(118224);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"PostgreSQL STARTTLS Support");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports encrypting traffic.");
  script_set_attribute(attribute:"description", value:
"The remote PostgreSQL server supports the use of encryption
initiated during pre-login to switch from a cleartext to an
encrypted communications channel.");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.2/protocol-flow.html#AEN96066");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/docs/9.2/protocol-message-formats.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:postgresql:postgresql");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("postgresql_detect.nasl");
  script_exclude_keys("global_settings/disable_test_ssl_based_services");
  script_require_ports("Services/postgresql", 5342);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

if (get_kb_item("global_settings/disable_test_ssl_based_services"))
  exit(1, "Not testing SSL based services per user config.");

app = "PostgreSQL";

# Get the ports that PostgreSQL has been found on.
port = get_service(svc:"postgresql", default:5342, exit_on_fail:TRUE);

# Find out if the port is open.
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Connect to the port.
soc = open_sock_tcp(port, transport:ENCAPS_IP);
if (!soc) audit(AUDIT_SVC_FAIL, app, port);

# All parameters in TDS are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Send the STARTTLS command.
soc = postgresql_starttls(socket:soc);
if (!soc) exit(1, "The " + app + " instance on port " + port + " didn't accept our STARTTLS command.");
set_kb_item(name:"postgresql/" + port + "/starttls", value:TRUE);

# Call get_server_cert() regardless of report_verbosity so the cert
# will be saved in the KB.
cert = get_server_cert(
  port     : port,
  socket   : soc,
  encoding : "der",
  encaps   : ENCAPS_TLSv1
);

# Clean up.
close(soc);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  info = "";

  cert = parse_der_cert(cert:cert);
  if (!isnull(cert))
    info = dump_certificate(cert:cert);

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
