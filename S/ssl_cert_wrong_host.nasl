#TRUSTED 228bdcbb5eaaf6e0783affd08736b39ef15e6448599dc93f5ea4e3c6f622a8565cdc8185b4b311918038a380e841558d8521e4b4040689c6d2a896dbf1cfaba07cd9902895a46de792be0c7ec29d95d26a00cf126a7901d697d6b5fcbf90bd5097ef576d71681e4f2942297cb63891c2b6d229049be0172f24d6ff60f323f876b72a1cfbd6a7fd9dfa7960d2b7aa80860452fa8946bb5dcb1f86391dec94cc71533370f01dda3b68286b80a13f2f0cf21e1106c2053667c2a5319d70c58e45135bb0d02dbfacaf31b24119ddec4294b6156b542e0d95e0f7c8b096df5142eaad956e35bfbc3ebaafced24cb49abf71d868681a7099c028fc657b17586a4a1d66e8ab2b4ee70909180ebb55314fbc21bca8804ec5965b366d5c1e3ef2b4f78a9f0582179d7c8a67c55bc9d49a75fa90077e192a38dd69fb8d66d881eb7cba7ad0c8505605959997f9c6c8d2136c3153272ba83cc6bcfdca88f04705f0d040decd7f8975e01f288de1fe12a691074f0bd4d390c6539baf5598d0021ef887e3e7b90ce45d6d733f38cc792eec77aff95548c9eda168b75f37e131a9190098e2992c8a02ade9569ec4bd9ad1e3f88939a45a6b0facd8fc5559c07a3cd81e19f2f2a087c2fc245b702cd228eb41273170e095b633216118b6c26945aa6bdb092e1ec51335342cda6a52b7c058fc9fb345fb5b3938185bce59ef0656f4d29e323ff909
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(45411);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");
 
 script_name(english:"SSL Certificate with Wrong Hostname");
 script_summary(english:"Checks that the X509 CN matches the target host.");
 
 script_set_attribute(attribute:"synopsis", value:
"The SSL certificate for this service is for a different host.");
 script_set_attribute(attribute:"description", value:
"The 'commonName' (CN) attribute of the SSL certificate presented for
this service is for a different machine.");
 script_set_attribute(attribute:"solution", value:
"Purchase or generate a proper SSL certificate for this service.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"SSL certificate for this service is for a different host.");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"General");

 script_dependencies(
   "ssl_supported_versions.nasl",
   "ssl_cert_CN_mismatch.nasl",
   "ifconfig_inet4.nasl",
   "ifconfig_inet6.nasl",
   "netbios_multiple_ip_enum.nasl",
   "wmi_list_interfaces.nbin"
 );
 if (NASL_LEVEL >= 4200)
   script_dependencies("alternate_hostnames.nasl");
 script_require_keys("SSL/Supported");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("resolv_func.inc");
include("ssl_funcs.inc");

get_kb_item_or_exit("SSL/Supported");

# Check if we know any names for the host.
addr = get_host_ip();
dns_name = get_host_name();
smb_name = get_kb_item("SMB/name");

if ( ! get_kb_item("Settings/PCI_DSS" ))  
{
if (dns_name == addr && (!smb_name || smb_name == addr))
  exit(1, "No hostnames are known for the remote target.");
}

# Compile a list of all the host's identities.
ids = make_list();

ifs = get_kb_item("Host/SMB/InterfaceList");
if (ifs)
{
  foreach line (split(ifs))
  {
    matches = pregmatch(string:line, pattern:"^ +- +[^=]+= *([^ /]+) */");
    if (!isnull(matches))
      ids = make_list(ids, matches[1]);
  }
}

kbs = make_list(
  "Host/ifconfig/IP4Addrs",
  "Host/ifconfig/IP6Addrs",
  "Host/Netbios/IP",
  "Host/alt_name",
  "Host/hostname"
);

foreach kb (kbs)
{
  list = get_kb_list(kb);
  if (!isnull(list))
    ids = make_list(ids, list);
}

for (i = 0; i < max_index(ids); i++)
{
  ids[i] = tolower(ids[i]);
}

ids = list_uniq(ids);

if (!get_kb_item("Settings/PCI_DSS") && max_index(ids) <= 0)
  exit(1, "No identities are known for the remote target.");

# Get a port that uses SSL or StartTLS.
port = get_ssl_ports(fork:TRUE);
if (isnull(port))
  exit(1, "The host does not appear to have any SSL-based services.");

# Check if we already have a match between this host and the
# certificate on this port.
if (get_kb_item("X509/" + port + "/hostname_match"))
  exit(0, "The certificate associated with port " + port + " matches the hostname.");

# Compile a list of all the Common Names and Alternate Names in the
# certificate.
names = make_list();

cns = get_kb_list("X509/" + port + "/CN");
if (!isnull(cns))
{
  cns = make_list(cns);
  names = make_list(names, cns);
}

ans = get_kb_list("X509/" + port + "/altName");
if (!isnull(ans))
{
  ans = make_list(ans);
  names = make_list(names, ans);
}

for (i = 0; i < max_index(names); i++)
{
  names[i] = tolower(names[i]);
}

names = list_uniq(names);

if (max_index(names) <= 0)
  exit(0, "No Common Names and no Subject Alternative Names were found in the certificate associated with port " + port + ".");

# Compare all names found in the certificate against all the
# identities of the host.
foreach name (names)
{
  if (substr(name, 0, 1) != "*.")
  {
    # Try an exact match of the names.
    if (is_same_host(a:name, fqdn:TRUE))
      exit(0, "The certificate associated with port " + port + " matches one of the hostnames exactly.");

    # Try an exact match of the identities.
    foreach id (ids)
    {
      if (is_same_host(a:name, b:id, fqdn:TRUE))
        exit(0, "The certificate associated with port " + port + " matches one of the host's identities exactly.");
    }
  }
  else
  {
    # Try a wildcard match of the identities.
    domain = tolower(substr(name, 1));
    foreach id (ids)
    {
      j = stridx(id, ".");
      if (j >= 0 && tolower(substr(id, j)) == domain)
        exit(0, "The certificate associated with port " + port + " matches one of the host's identities with a wildcard.");
    }
  }
}

# Report our findings.
if (max_index(ids) > 0)
  id_s = "ies known by Nessus are";
else
  id_s = "y known by Nessus is";

report =
  '\nThe identit' + id_s + ' :' +
  '\n' +
  '\n  ' + join(sort(ids), sep:'\n  ') +
  '\n  ' + get_host_name() + 
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

security_warning(port:port, extra:report);
