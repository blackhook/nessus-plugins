#TRUSTED 2c06d403508799d0d2d5f2d5210e3c358f74a3e2dc13701741d1197c812e7475830e5b0e0ad22566aa13b1ba0a32cc68ec82bd0d69baf01ef3489b1370381caca8add43e08017a1f3eb8b6a454a9010a2db4d3b50ca8a300178016b2de993692f0ac02f8a33e7c9163c71cecbb48a232e9607a601cf6b2dded398f664ddf8f80ae9cd26724a31266cce9c4ffdb17d7ea32a999495127a7673760c4a392882f1bb3649f30a4dc476c02922af7496daae28b9d9bd5bd4abe5d252a00d4fd462c731493308ad27ee5f99f2bf1e9d8ac3cc3107d3e7444fb9c5844b958557bd7f35ac44d9af6865a30bbfe7d9c785b938ab14c5f0310be5afce3583d7525a82ed97040ea8c2061f3b4c0e661c4724b8f0d57fd5f68542670c9f379c37436815fb655185b3e32f258e76e64760847732fbf5fdea8514e42fbbe31a60dfab665312b5a8e1e84ed99179ea792de8fa080d73f4589c76fb1b1bbd87c6f8a82dfeb623d651e605d5fd419c34cc09508231564558d612f235607ef0f3ce68bfb718622c89dea82302598fa3ad1421baa707b7e4bdeaa6370cc22c65e7c115c4904f15d5879f41e2aa869418ece8f9c32ae90f7b97635b678e9766e0a49d44b6e379dbf4cfba4119877c3be1c13a4be16ae615677ab370c1b2034daafb54c900be57ef0cbaa8d921cfe43b8d5c9c27870006fa04eaef31b82cc0b3a5840c3b62ae9f9663a9f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(47557);
 script_version("1.27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/16");
 
 script_name(english:"Host Fully Qualified Domain Name (FQDN) Resolution (XML tag)");
 
 script_set_attribute(attribute:"synopsis", value:
"This internal plugin adds an XML tag in the report about the remote
host.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to resolve the fully qualified domain name (FQDN) of
the remote host. This plugin, which does not show up in the report,
writes the IP and FQDN of this host as an XML tag in the .nessus v2
reports.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2011/07/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 script_category(ACT_SETTINGS);
 script_family(english:"Settings");
 
 script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

 exit(0);
}

include("agent.inc");
include("resolv_func.inc");
include("spad_log_func.inc");

hostname = NULL;

# Agent
if (agent())
{
  hostname = agent_fqdn();
  if (!valid_fqdn(fqdn:hostname)) exit(1, "Failed to determine asset's FQDN via agent.");

  replace_kb_item(name:"myHostName", value:hostname);
  set_kb_item(name:"Host/agent/FQDN", value:hostname);

  report_xml_tag(tag:"host-fqdn", value:hostname);
  replace_kb_item(name:"Host/Tags/report/host-fqdn", value:hostname);
}
# Nessus scanner
else
{
  # IP Address
  host_ip = get_host_ip();
  if (!empty_or_null(host_ip) && is_host_ip(name:host_ip))
  {
    report_xml_tag(tag:"host-ip", value:host_ip);
    replace_kb_item(name:"Host/Tags/report/host-ip", value:host_ip);
  }
  # rDNS lookup
  rdns = NULL;
  if (defined_func("get_host_fqdn"))
  {
    rdns = get_host_fqdn();
    if (!empty_or_null(rdns) && !is_host_ip(name:rdns))
    {
      report_xml_tag(tag:"host-rdns", value:rdns);
      replace_kb_item(name:"Host/Tags/report/host-rdns", value:rdns);
    }
  }

  # If the target was specified as an IP address and rDNS fails to return a
  # FQDN that forward resolves to the target, use the IP as a Host: header for HTTP
  if (defined_func("get_host_fqdn") && defined_func("resolv") &&
      !empty_or_null(rdns) && !empty_or_null(host_ip))
  {
    if(get_kb_item("global_settings/enable_plugin_debugging"))
    {
      msg = "Determining whether to use IP for Host: header instead of fqdn.";
      msg += '\n\tget_host_name() returns: ' + get_host_name();
      msg += '\n\tis_same_host(a:ip, b:rdns) returns: ' + is_same_host(a:host_ip, b:rdns);
      msg += '\n\trdns ';
      if(rdns == host_ip) msg += 'EQUALS';
      else                msg += 'DOES NOT EQUAL';
      msg += ' host_ip\n\n';
      log_name = ((SCRIPT_NAME - ".nasl") - ".nbin") + "_resolv_func.log";
      spad_log(message:msg,name:log_name);
    }

    if(get_host_name() == rdns && !is_same_host(a:host_ip, b:rdns) && rdns != host_ip)
    {
      host_replacement = '';
      if(TARGET_IS_IPV6) host_replacement += '[';
      host_replacement += host_ip;
      if(TARGET_IS_IPV6) host_replacement += ']';

      replace_kb_item(name:"Host/HTTP/bad_rdns_host_use_ip", value: host_replacement);
    }
  }

  # FQDN - use user-specified FQDN instead of rDNS lookup otherwise use rDNS
  hostname = determine_fqdn();
  if (empty_or_null(hostname)) exit(1, "Failed to determine asset's FQDN.");

  report_xml_tag(tag:"host-fqdn", value:hostname);
  replace_kb_item(name:"Host/Tags/report/host-fqdn", value:hostname);

}
