#TRUSTED 538dccc906b9f78709bce8c08509acb33f3341fad11172781cc725994f196d22e707473e0693f8eaaca2d4b6d1c6149ef2bad2b820a419000d1f3a3e05af77132b4d663b3ef5bf5070ef3ccb580526623eebd2fe5475062a6f564ef2ff80bb847f23f8818e44fdc889b4dc278ae93a7d651677c0d873f6c0a73f0b45c9507100d4d49edaa965d7d3eaf770a4464d795ef09eda1dd46636714c664b8e14d3c91082bc5abe9751049cd1869c21031cd8aa9cdd591f410ffc6a948d013e92cddbe7893bdf588dcf4f9f1202d92f11ebb49077a9997a4fe24d000ba3559dfad46ca1385abc0bd5c86e76af0fdb5f4ea76b793afad9257c41b493abfd601800971f439b644841dce26ec11554581eeb500989829edadee00a37ef04f36e8feea1a645f92271838752d65a595d9bf9dc7bd83f3949621c43516833ce4b29ed5f6bc50e4287af35d32268371e95634ec297cb73917942eff4726c30cde2c95a18b8177cddaf552788d1864fd5cf45d7b858eb2c476ed79b5036201bf12edcc0c617b474256a9ad6f045cf259565c7439fdea03ab2446e114b595a709c42ad93181ff9e3f6870f3d7f9b04246229975e386a727e0eed48f765207a04d8ff69189dcbce866bc7657bc63e3dd69cd27765eedadf268b37ab34378a66683c5822a6524bab65796c82632f3ebc4f7d3943a36098da955ad3bdc85918ea518a3fc29056a16a0c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (!defined_func("recvfrom") || !defined_func("sendto")) exit(1, "recvfrom() / sendto() not defined.");

if (description)
{
  script_id(59465);
  script_version("1.14");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2012-4068");
  script_bugtraq_id(53330);

  script_name(english:"Citrix Provisioning Services Unspecified Request Parsing Remote Code Execution (CTX133039) (uncredentialed check)");
  script_summary(english:"Checks version in bootstrap file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application running that is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Provisioning Services running on the remote
Windows host is affected by a remote code execution vulnerability in
the SoapServer service due to improper validation of user-supplied
input when parsing date and time strings. An unauthenticated, remote
attacker can exploit this to cause a buffer overflow, resulting in a
denial of service condition or the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX133039");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch from the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:provisioning_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tftpd_detect.nasl");
  script_require_udp_ports(69, 6969);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("byte_func.inc");
include("misc_func.inc");
include("tftp_func.inc");

function ctxpvs_two_stage_get(port, path)
{
  local_var s, sport, file, response, id, data, dport, rlen, i, src_ip, num_chunks;

  file = "";
  rlen = NULL;

  if (isnull(port)) port = 6969;

  if (known_service(port:port, ipproto:"udp")) return NULL;
  if (!get_udp_port_state(port)) return NULL;

  s = bind_sock_udp();
  if (!s) audit(AUDIT_SOCK_FAIL, 'udp', 'unknown');

  sport = s[1];
  s = s[0];

  sendto(socket:s, data:'\x08\x17' + path + '\x00', dst:get_host_ip(), port:port);

  num_chunks = 0;
  while (TRUE)
  {
    response = recvfrom(socket:s, port:sport, src:get_host_ip());
    if (!response)
    {
      file = "";
      break;
    }
    dport = response[2];
    src_ip = response[1];
    response = response[0];
    if (src_ip != get_host_ip() || strlen(response) < 5 || substr(response, 0, 1) != '\x08\x97')
    {
      file = "";
      break;
    }
    id = substr(response, 2, 3);
    data = substr(response, 4);
    if (isnull(rlen)) rlen = strlen(data);

    sendto(socket:s, data:'\x08\xD7' + id, dst:get_host_ip(), port:dport);

    file += data;
    num_chunks++;

    # Allow up to 200 chunks to be received.
    if(strlen(data) != rlen || num_chunks > 200) break;
  }
  if (strlen(file) == 0)
  {
    return NULL;
  }
  else
  {
    for(i = 0; i < strlen(file); i++)
    {
      # Returned file needs XORed by 0xFF to decode.
      file[i] = mkbyte(getbyte(blob:file, pos:i) ^ 0xFF);
    }
    register_service(port:port, ipproto:"udp", proto:"citrix_two_stage_bootsrv");
    return file;
  }
}

function ctxpvs_version()
{
  local_var version_string, loc, version, i, file;

  file = _FCT_ANON_ARGS[0];

  version_string = "Provisioning Services bootstrap v";

  loc = stridx(file, version_string);

  if (loc == -1)
  {
    return NULL;
  }

  loc += strlen(version_string); # skip to version number
  version = "";
  for (i = loc; i < strlen(file); i++)
  {
    if (ord(file[i]) == 0x00) break;
    version += file[i];
  }

  if(strlen(version) == 0)
  {
    return NULL;
  }

  version = chomp(version);
  if (version =~ "^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$")
  {
    return version;
  }
  else
  {
    return NULL;
  }
}

if ( TARGET_IS_IPV6 ) exit(1, "IPv6 not supported");

file = NULL;
version = NULL;

file = ctxpvs_two_stage_get(path:'tsbbdm.bin');
if (!isnull(file))
{
  version = ctxpvs_version(file);
}

# If we couldn't retrieve a bootstrap file through the two-stage
# boot service  or determine version from it then try tftp.
if (isnull(file) || isnull(version))
{
  port = get_service(svc:'tftp', ipproto:"udp", exit_on_fail:TRUE);

  # Citrix tftp doesn't obey block size and always uses 512.
  # Override 1024 used in tftp_func.inc to make Citrix happy.
  TFTP_BLOCK_SIZE = 512;

  file = tftp_get(port:port, path:'ARDBP32.BIN');

  if (isnull(file)) exit(0, "The version of Citrix Provisioning Services could not be determined.");
  version = ctxpvs_version(file);
}

if (isnull(version)) audit(AUDIT_VER_FAIL, 'the bootstrap file');

fix = NULL;

v = split(version, sep:'.', keep:FALSE);

for (i=0; i < max_index(v); i++)
  v[i] = int(v[i]);

if (v[0] < 5 || (v[0] == 5 && v[1] < 6)) fix = '6.1.0.1082';
if (version =~ '^5\\.6\\.' && ver_compare(ver:version, fix:'5.6.3.1349') == -1) fix = '5.6.3.1349';
else if (version =~ '^6\\.0\\.0' && ver_compare(ver:version, fix:'6.0.0.1083') == -1) fix = '6.0.0.1083';
else if (version =~ '^6\\.1\\.0' && ver_compare(ver:version, fix:'6.1.0.1082') == -1) fix = '6.1.0.1082';

if (!isnull(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:54321, extra:report);
  }
  else security_hole(port:54321);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, 'Citrix Provisioning Services', version);
