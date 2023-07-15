#TRUSTED 8cb6317541a2820bd1dca934d1ae498aeea1c869ae4754cc163e86d73e98e07827fa80021a51a801df8a75d67b6b170c68110be0c4544e17dad2e477d22932bddb6bcb0af454bb25cb0242a581aa21a639ef453fb7b24c541e0fb34495013b3e0dd9a8d26486648a5babe190e072f0f0e61b1aa74632a17cc5af0fcffe835969c8ac5b6ec71c616d931f608ed265d625d002dc746bedc68acc035c1f960efbd4b8c83b5d343e603eac306826f5f13c0a2be3424d04ba086284f9ccfd14237759fffcc51c0a17949d88c53664f2a974826835185d7d3108cc7319ff9630c05a507fb28c8276bef08f23e2e36fcb006349d663bae10721abe6099a50c4f476ca0a496b60e9bccdcd456aadddf39c113989cfa9f3c7fe21402107697bf54bb704f89d34feff7b36f315ef3ee76da268b0100c74c28e3d24ef5c41d5fd8619332d2033451573507c8862a5b4de634b7e5eda08358e2f5a423e2faece90ea920181c33bd43af7551d204b5dca6de4ebd21a3391d9d21efde6076317f4922591b235d8a9b1c0669b680359db36b495dee09ceed5693da861950bb8bca7d0766a08cba2272f61ccafe57736fd531ef23d6e82fa87a926577cd9f199fd8dcf1939e706c9bdf154099a7cadb6a46b59a9ad2b856c730e92399c4e2be6b3956b20262069cce6814d29eaf4912006a63bf50173eb5490388aa9c6d4b4b8a6aa894b07f689f7
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(69482);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Microsoft SQL Server STARTTLS Support");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports encrypting traffic.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server service supports the use of
encryption initiated during pre-login to switch from a cleartext to an
encrypted communications channel.");
  script_set_attribute(attribute:"see_also", value:"https://msdn.microsoft.com/en-us/library/dd304523.aspx");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mssqlserver_detect.nasl");
  script_exclude_keys("global_settings/disable_test_ssl_based_services");
  script_require_ports("Services/mssql", 1433);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

if (get_kb_item("global_settings/disable_test_ssl_based_services"))
  exit(1, "Not testing SSL based services per user config.");

app = "Microsoft SQL Server";

# Get the ports that MSSQL has been found on.
port = get_service(svc:"mssql", default:1433, exit_on_fail:TRUE);

# Find out if the port is open.
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# Connect to the port.
soc = open_sock_tcp(port, transport:ENCAPS_IP);
if (!soc) audit(AUDIT_SVC_FAIL, app, port);

# All parameters in TDS are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Send the STARTTLS command.
soc = mssql_starttls(socket:soc);
if (!soc) exit(1, "The " + app + " instance on port " + port + " didn't accept our STARTTLS command.");
set_kb_item(name:"mssql/" + port + "/starttls", value:TRUE);

# Call get_server_cert() regardless of report_verbosity so the cert
# will be saved in the KB.
cert = get_server_cert(
  port     : port,
  socket   : soc,
  encoding : "der",
  encaps   : ENCAPS_TLSv1
);

if(isnull(cert)) {
  close(soc);
  soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if (!soc) audit(AUDIT_SVC_FAIL, app, port);

  soc = mssql_starttls(socket:soc);
  cert = get_server_cert(
    port     : port,
    socket   : soc,
    encoding : "der",
    encaps   : ENCAPS_TLSv1_2
  );
}

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

  version = get_kb_item("MSSQL/" + port + "/Version");
  instance = get_kb_item("MSSQL/" + port + "/InstanceName");
  if(!isnull(version) || !empty_or_null(instance))
  {
    report += '\n';
    if(version) report += '\n  SQL Server Version   : ' + version;
    if(!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  }
}

security_note(port:port, extra:report);
