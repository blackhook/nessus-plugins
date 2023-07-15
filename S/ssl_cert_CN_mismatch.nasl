#TRUSTED 19d821566665bdb4dfead7907389ffb7d896e50fcf6dc6a77ffe2f5f74530be3b2d6b2a8f7bd1d6654cf8ea7d8742040c5ff6b641d52f79e37c88f423d114ede72e4f3206cb73555d121115e01a8c08a97eac293b4476c892c9f75429fae277dc0aff18f539759f09281f2a788fb103521cbe6ce7e6e8a636fae53eb838fb9d1bd17c59152ce706bfb7dfef9e65a7ee3a10b616bd42f57829543f4777f9e2c83577917b7a32a2b7a6843529099e4cd25df7cc7d24a61bc961f03125fe35ee75734dc3096c050018ed4a0727e36ad26dd6e5d3190c540816ac309090ed526f6054731554c9fb23181dfb2bb5cf22616c34185e96e9e716732c79fc12a7d9b2dc1e6f7f87205100872069dcbb0d699262d63077ec795a1c8b3cef3a5e53fcef7e7530b32aec3553c0930c33e3bff08b9213a4ce940863a60c755df41c1fe3480a25e1380f4148305d829cfc35d21629207800e54db320ab859ed641dd6af6c14fa8af6be04c30dfaa28206151eb2344ef4b94c5257b3cbddf8898e517d1b0dfeab4543fea2de4f8cef2d8f90ec029fbec4e9c6d9c84f86aaacf3b760934ca2effe7afaf776fbacbfce9819860636b62aeda345eaed0c1e19ed94764623c621673caa83de89660b3e3b1d4e1a9c9a8167261e95bd60cf5ae38be643771502be2bc064560bb935c16ec9dc6925d10a89ceec57ed2996853e052d934e6d6f9637c780
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3208 ) exit(0);

include("compat.inc");

if (description)
{
 script_id(45410);
 script_version("1.26");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/09");

 script_name(english:"SSL Certificate 'commonName' Mismatch");
 script_summary(english:"Compare the X509 CN with the hostname.");

 script_set_attribute(attribute:"synopsis", value:
"The 'commonName' (CN) attribute in the SSL certificate does not match
the hostname.");
 script_set_attribute(attribute:"description", value:
"The service running on the remote host presents an SSL certificate for
which the 'commonName' (CN) attribute does not match the hostname on
which the service listens.");
 script_set_attribute(attribute:"solution", value:
"If the machine has several names, make sure that users connect to the
service through the DNS hostname that matches the common name in the
certificate.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"General");

 script_dependencies("ssl_supported_versions.nasl", "find_service_dtls.nasl");
 script_require_ports("SSL/Supported", "DTLS/Supported");

 exit(0);
}

include("global_settings.inc");
include("resolv_func.inc");
include("x509_func.inc");

if(!get_kb_item("SSL/Supported") && !get_kb_item("DTLS/Supported"))
  exit(1, "Neither the 'SSL/Supported' nor the 'DTLS/Supported' flag is set.");

in_flatline = get_kb_item("TESTING_ssl_cert_CN_mismatch");

# Compile a list of names for this host from all name services.
host_names = make_list();

if(!in_flatline)
  addr = get_host_ip();
else
  addr = get_kb_item("TESTING_ssl_cert_CN_mismatch_IP");

# NetBIOS Name Service.
name = get_kb_item("SMB/name");
if (name && name != addr)
{
  # Add the short name.
  host_names = make_list(host_names, tolower(name));

  domain = get_kb_item("SMB/domain");
  if (domain)
  {
    name += "." + domain;

    # Add the full name.
    host_names = make_list(host_names, tolower(name));
  }
}

# Domain Name Service.
if(!in_flatline)
  name = get_host_name();
else
  name  = get_kb_item("TESTING_ssl_cert_CN_mismatch_hostname");

if (name != addr)
  host_names = make_list(host_names, tolower(name));

host_names = list_uniq(host_names);

# Get list of ports that use TLS, DTLS or StartTLS.
pp_info = get_tls_dtls_ports(fork:TRUE, dtls:TRUE);
port = pp_info["port"];
if (isnull(port))
  exit(1, "The host does not appear to have any TLS or DTLS based services.");

if(pp_info["proto"] == 'tls')
  use_dtls = FALSE;
else if(pp_info["proto"] == 'dtls')
  use_dtls = TRUE;
else
  exit(1, "A bad protocol was returned from get_tls_dtls_ports(). (" + port + "/" + pp_info["proto"] + ")");

# Get the server's certificate.
cert = get_server_cert(port:port, encoding:"der", dtls:use_dtls);
if (isnull(cert))
  exit(1, "The certificate associated with " + pp_info["l4_proto"] + " port " + port + " cannot be retrieved.");

# Parse the server's certificate.
cert = parse_der_cert(cert:cert);
if (isnull(cert))
  exit(1, "The certificate associated with " + pp_info["l4_proto"] + " port " + port + " cannot be parsed.");

# Extract the Common Names from the certificate.
cns = make_list();

tbs = cert["tbsCertificate"];
subject = tbs["subject"];
foreach field (subject)
{
  if (field[0] != "2.5.4.3")
    continue;
  if ( isnull(field[1]) )
    continue;

  cn = field[1];
  cns = make_list(cns, tolower(cn));
  set_kb_item(name:"X509/" + port + "/CN", value:cn);
}

cns = list_uniq(cns);

# Extract the Alternate Names from the certificate.
ans = make_list();

extensions = tbs["extensions"];
foreach ext (extensions)
{
  if (ext["extnID"] != "2.5.29.17")
    continue;

  foreach value (ext["extnValue"])
  {
    name = value["dNSName"];
    if(isnull(name))
      name = value["iPAddress"];
    if(isnull(name))
      continue;

    set_kb_item(name:"X509/" + port + "/altName", value:name);
    ans = make_list(ans, tolower(name));
  }
}

ans = list_uniq(ans);

# Combine all the names so we can process them in one go.
cert_names = list_uniq(make_list(cns, ans));
if (max_index(cert_names) <= 0)
  exit(0, "No Common Names and no Subject Alternative Names were found in the certificate associated with " + pp_info["l4_proto"] + " port " + port + ".");

# We cannot test if we do not know the hostname, unless we're in PCI
# mode where we're expected to produce a report regardless.
if (!get_kb_item("Settings/PCI_DSS") && max_index(host_names) <= 0)
  exit(1, "No host name is available for the remote target.");

# Compare all names found in the certificate against all names and
# addresses of the host.
foreach cert_name (cert_names)
{
  foreach host_name (host_names)
  {
    # Try an exact match of the names.
    if (cert_name == host_name)
    {
      set_kb_item(name:"X509/" + port + "/hostname_match", value:TRUE);
      exit(0, "The certificate associated with " + pp_info["l4_proto"] + " port " + port + " matches one of the hostnames exactly.");
    }

    i = stridx(cert_name, ".");
    if (i == 1 && cert_name[0] == "*")
    {
      # Try a wildcard match of the names.
      j = stridx(host_name, ".");
      if (j >= 0 && substr(host_name, j) == substr(cert_name, i))
      {
        set_kb_item(name:"X509/" + port + "/hostname_match", value:TRUE);
        exit(0, "The certificate associated with " + pp_info["l4_proto"] + " port " + port + " matches one of the hostnames with a wildcard.");
      }
    }
    else
    {
      # Try an address-based match of the name.
      if (is_same_host(a:cert_name, fqdn:TRUE))
      {
        set_kb_item(name:"X509/" + port + "/IP_addr_match", value:TRUE);
        exit(0, "The certificate associated with " + pp_info["l4_proto"] + " port " + port + " matches the one of the host's addresses exactly.");
      }
    }
  }
}

# If we don't know any names for the host, consider its address as its
# name in the report.
if (max_index(host_names) <= 0)
  host_names = make_list(addr);

# Report our findings.
if (max_index(host_names) > 1)
  s = "s known by Nessus are";
else
  s = " known by Nessus is";

report =
  '\nThe host name' + s + ' :' +
  '\n' +
  '\n  ' + join(sort(host_names), sep:'\n  ') +
  '\n';

if (cns && max_index(cns) > 0)
{
  if (max_index(cns) > 1)
    s = "s in the certificate are";
  else
    s = " in the certificate is";

  report +=
    '\nThe Common Name' + s + ' :' +
    '\n' +
    '\n  ' + join(sort(cns), sep:'\n  ') +
    '\n';
}

if (ans && max_index(ans) > 0)
{
  if (max_index(ans) > 1)
    s = "s in the certificate are";
  else
    s = " in the certificate is";

  report +=
    '\nThe Subject Alternate Name' + s + ' :' +
    '\n' +
    '\n  ' + join(sort(ans), sep:'\n  ') +
    '\n';
}

security_note(port:port, proto:tolower(pp_info["l4_proto"]), extra:report);
