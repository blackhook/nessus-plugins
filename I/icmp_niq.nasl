#TRUSTED 088ad3bc1d8759cfe73e970e10bb6f7e20a9bffab9900f1c5a9c690ebda7fbdffe3ebc2894855fde5655d9b6715891ff2e2b67ab0505bfb796e1db3c64f1c39ab90b36abd649c6825f38fb055b626e61e6f05a6608364c1c21c6701b86949dc803354a05aaccbdab41f9e1c176e6dc55a0c6937708818e118377c2209e8c120aa2213b2a8f7793a63bf1fa800888e23e53b11bcc7fb7b3c8646ff78f2e68241434e5809883e5f70d225d1697a9baf63a165cc0d8d22e9a0e8cd48251711f8d928f04055f58a27002d37a5fcab5e3d05b29deb01a5bc55d29ab9284ba6ef0990e7482751a3fb80cc30e37985581213764b996947c7c5ad74acf6e184342e84c717b9e19e673cc38d78dd1938485f5e5082f07050db29c65037658619db5bfe7edc92c754842fed9189ad10f26c2155d99658c09ebbc3d70fbea6f3e8e70a8318c5caa931f834ab59f7903e0195b457feb4d21b19c3b0cf85f7ddbc86588096ea0ff2dec1581b24f2d4a1c7a85085d6692acd719a4d0eef9be8aaa4d66a0810555aead32f74c3b76d6412c5fd23120791a58c2239fcf7cb9b29145ef4a5e31391ffa4cffd7082eada22539ff041b0cc13bad9ff4d1bbd70037ee4fea05777518b4e284001627437f4f624b32ef518ef4b13b82ebb88e039dfab22a72e974cdf1aa14ac8f0698aa6ef76098a652fc22778dcc34d0071fa37b2e6b08b7889124fda0
#TRUST-RSA-SHA256 5ae3bc630d637b10a6086c5c0478f8cfdb2a60fd16a6d7cce455397bae36cc61e21e71fd1d799689cf7a569067171ed5478b96f714ea61236affaebacf7ec70574fb2af6bc3c0d2c6311786c91d43bedde31f00c4f627a862c8f3841e38ccff1e180762766123648d22fb282abd2861b2a0c63876be09148b77d441504d2ba5dad26695384560eb63e9e1cf5f642a115973a2b93abb404f81c1eb79409111c5e202b8ea2003f33cae21103f47e70d59d93ad9788a47719e2e4b1d0155f0310e4004b3960cc0965c1282106124265ebc3fc9d6e59ab8182e52d86ad0f8acbd6c66550d773f16a87f5efd79b24cf89edab8d2e20b739cc33b790a41c631667fce510488bd90b065c97617c5b6d808afe6b60e6e62b4cdc5e046aff042e735e0e0c15ce5960d77d4624cf166ed5d5467ba81fb9ebfb8e3dc7a84502956edbc56966770d64df670300b3a3fe9d96afaac5c5d8473777990667fc8ce289fdfeeded924074292e79b7fdb728dccba1ce9c60612df477b5303b776143f86c938256a9bfbe993303f0058a5386c590bb351d6ad79977e71ef3d05a3e3bc9915e6e5cc8de2fa13885c63fcc6c02e5cd067ca6c2b2c2a6c85ad97f644bf5167450e3a667574344a51a67104de8df65eaf0b3cac78a642abb6b2043b9df7ee24d6c7657c417dd7f2985e52b994765b68815541ce6aff637142ba0fa476ab597e95bcc526595
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(45399);
 script_version("1.7");
 script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/28");

 script_name(english:"ICMP Node Information Query Information Disclosure");
 script_summary(english:"Sends an ICMP_NIQ");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host answers to an ICMPv6 Node Information Query and
responds with its DNS name, the list of IPv4 addresses and the list of
IPv6 addresses to which it is bound. 

An attacker can use this information to understand how the network is
architected, which may help him bypass filters.");
 script_set_attribute(attribute:"solution", value:
"Reconfigure the remote host so that it does not answer to these
requests.  Set up filters that deny ICMP packets of type 139." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/04/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");
 script_family(english:"General");
 
 exit(0);
}


include('raw.inc');

if ( ! TARGET_IS_IPV6 ) exit(0, "The target is not accessed via IPv6.");

function mk_icmp_niq(csum, nonce, qtype)
{
  var icmp;

  icmp = mkbyte(139) + # type
        mkbyte(0)   + # Code
        mkword(csum)   + # Checksum
        mkword(qtype) + # Query Type
        mkword(0x003e) + # Flags
        nonce + 
        get_host_raw_ip();
  return icmp;
}

function csum()
{
  return inet_sum(this_host_raw() +
            get_host_raw_ip() +
            '\0\0' +
            mkword(strlen(_FCT_ANON_ARGS[0])) +
            '\0\0\0' +
            mkbyte(58) +
            _FCT_ANON_ARGS[0]);
}

function icmp_niq()
{
  var i, rep;
  var pkt;
  var nonce, icmp;
  var qtype;
  var hostIpNoScope, dstIp, dstIpNoScope;

  qtype = _FCT_ANON_ARGS[0];
  nonce = mkdword(rand()) + mkdword(rand());
  icmp = mk_icmp_niq(qtype:qtype, csum:0, nonce:nonce);
  icmp = mk_icmp_niq(qtype:qtype, csum:csum(icmp), nonce:nonce);
  pkt = mkpacket(ip6(ip6_nxt:0x3a), payload(icmp));

  dstIp = compat::this_host();
  dstIpNoScope = ereg_replace(string:dstIp, pattern:"(.*)(%.*)", replace:"\1");
  hostIpNoScope = ereg_replace(string:get_host_ip(), pattern:"(.*)(%.*)", replace:"\1");
  for ( i = 0 ; i < 3 ; i ++ )
  {
    # Commenting out due to compilation erros on older versions
    #if (defined_func('get_host_ip_ex'))
    #  rep = inject_packet(packet:link_layer() + pkt, filter:"ip6 and icmp6 and src " + get_host_ip_ex(options: {"flags": IPFMT_IP6_NO_SCOPE}) + " and dst " + dstIpNoScope, timeout:2);
    #else
      rep = inject_packet(packet:link_layer() + pkt, filter:"ip6 and icmp6 and src " + hostIpNoScope + " and dst " + dstIpNoScope, timeout:2);

  if ( isnull(rep) ) continue;
  if ( strlen(rep) < 40 + strlen(link_layer())) continue;
  if ( ord(rep[40 + strlen(link_layer())]) == 140 ) break;
  rep = NULL;
  }
  if ( rep == NULL ) exit(0); # Not supported
  if ( ord(rep[41 + strlen(link_layer())]) != 0 ) return NULL;
  if ( strlen(rep) <= 56 + strlen(link_layer())) return NULL;
  return substr(rep, 56 + strlen(link_layer()), strlen(rep) - 1 );
}

function ip6_addr()
{
  var str;
  var i;
  var oct;
  var ret;

  str = _FCT_ANON_ARGS[0];
  for ( i = 0 ; i < strlen(str) ; i += 4 )
  {
    if ( strlen(ret) > 0 ) ret += ":";
    oct = substr(str, i, i + 3);
    while ( strlen(oct) && oct[0] == "0" ) oct = substr(oct, 1, strlen(oct) - 1);
    if ( oct == "0" ) oct = "";
    ret += oct;
  }
  ret = ereg_replace(pattern:"::+", replace:"::", string:ret);
  return ret;
}

function ip4_addr()
{
  var ip;
  ip = _FCT_ANON_ARGS[0];
  return strcat(ord(ip[0]), '.', ord(ip[1]), '.', ord(ip[2]), '.', ord(ip[3]));
}


var DNS = 2;
var IP6 = 3;
var IP4 = 4;

if ( isnull(link_layer()) ) exit(0, "Can not use packet forgery over this interface.");

var rep = icmp_niq(DNS);
var report = '', pos, name, len, dns_name, ip6, ip4, ttl, addr;
if ( rep != NULL )
{
  pos = 4;
  name = "";
  while ( pos < strlen(rep) )
  {
    if ( pos + 1 >= strlen(rep) ) break;
    len = getbyte(blob:rep, pos:pos);
    pos ++;
    if ( len == 0 ) break;
    if ( strlen(name) ) name += ".";
    if ( pos + len >= strlen(rep) ) break;
    name += substr(rep, pos,  pos + len - 1);
    pos += len;
  }
  if ( strlen(name) ) report += '\n+ The DNS name of the remote host is :\n\n' + name + '\n';
  dns_name = name;
}

rep = icmp_niq(IP6);
if ( rep != NULL )
{
  pos = 0;
  ip6 = '';
  while ( pos < strlen(rep) )
  {
    if ( pos + 4 >= strlen(rep) ) break;
    ttl = getdword(blob:rep, pos:pos);
    pos += 4; 
    if ( pos + 16 > strlen(rep) ) break;
    addr = substr(rep, pos, pos + 15);
    pos += 16; 
    set_kb_item(name:"Host/ICMP/NIQ/IP6Addrs", value:ip6_addr(hexstr(addr)));
    ip6 += ip6_addr(hexstr(addr)) + " (TTL " + ttl + ')\n';
  }
  if ( strlen(ip6) ) report += '\n+ The remote host is bound to the following IPv6 addresses :\n\n' + ip6 + '\n';
}

rep = icmp_niq(IP4);
if ( rep != NULL )
{
  pos = 0;
  ip4 = '';
  if ( strlen(dns_name) && dns_name >!< rep ) # Mac OS X bug
  {
    while ( pos <= strlen(rep) ) 
    {
      if ( pos + 4 >= strlen(rep) ) break;
      ttl = getdword(blob:rep, pos:pos);
      pos += 4;
      if ( pos + 4 > strlen(rep) ) break;
      set_kb_item(name:"Host/ICMP/NIQ/IP4Addrs", value:ip4_addr(substr(rep, pos, pos + 3)));
      ip4 += ip4_addr(substr(rep, pos, pos + 3)) + ' (TTL ' + ttl + ')\n';
      pos += 4;
    }
    if ( strlen(ip4) ) report += '\n+ The remote host is bound to the following IPv4 addresses :\n\n' + ip4 + '\n';
  }
}

if ( strlen(report) ) security_note(port:0, proto:'icmp', extra:report);
