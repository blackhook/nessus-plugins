#TRUSTED 206cb7b324b54b616c3f3e152075344abf67b49a3a87d4b376b48ea17b4bcf69b3398110b5aed0b534fde5ed1f5d580ca62312c01f9cdf1b47e5a73430e0b14b8267760d294bfe2bb28cf86bd9224693c156ad533d37928a0163c406bf25d7114fae01ae7b7aae9041e61bb9f9144d3e534924ade6f7ee69a7bedf7520553dc138461b86cb1815227bba710d8c2ae4776189ab44afe9bad16856782c0566ceb76649112bf6e4028044618568c019ab058d1ff15e2798738564a1145bf126b24304b94a530adca9a05c76779340e77e2a2adc7cd26595eebba6309c56e9c8606592b2b1dd981d3cb82e0926f5d6d7d5813d067ac9a9ea1dfc447c19637e7dc5ef4a4fe776f022ec078b0900f3a94c016ee615aefcfc7939b82225de69848d227d4bac5ca2fce21a9654fa60b03788def0ba5ae7446d6141f8d587635a7270dd4eef0ac2e7be27020ccb7e62123b89edb6ee3b56ebf8b5a9d7d9e7311cc0a56ae34946bd32c15957ec82f18751ac25aae72eb26611175db14bc97355fefed342fbe7c5e161dd915f9efe7eafbfae1afc6231657179cd46c710d92e98a0dca78562614b618e09247d6b1c856ec88bbd6789961f7e8204113ebdf46fbb5d196e6b70959aebf76e78f0ac96291b40823cb18412560ca1786425e955cd16692bf874b8c606bafccc5d36721f2151e6a05c95f24cbb92f7bb795df7e6e2f04539c30e7f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(122316);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/11");

  script_name(english: "Ncat TLS Listener");
  script_summary(english: "Determines the presence of Ncat listening over TLS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host may have been compromised." );
  script_set_attribute(attribute:"description", value:
"This host seems to be running an instance of Ncat that is listening
over TLS.  Ncat is an open source networking tool that can be used
as a backdoor to allow unauthorized entry and control of the remote
host

An attacker may use it to steal your passwords, modify your data, and
prevent you from working properly.");
  script_set_attribute(attribute:"solution", value:
"Reinstall your operating system or restore your system from known
clean backups.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"The presence of a backdoor is an indicator of complete system compromise.");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "Backdoors");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "find_service2.nasl", "ssl_certificate_chain.nasl");
  script_require_ports("Services/unknown");
  exit(0);
}

include("ssl_funcs.inc");
include("x509_func.inc");

if(get_kb_item("global_settings/disable_service_discovery"))
  exit(0, 'Service discovery is disabled.');

var ports = get_unknown_svc_list();

if(empty_or_null(ports))
  audit(AUDIT_SVC_KNOWN);

foreach port(ports)
{
  if(!service_is_unknown(port:port) ||
     !get_port_state(port) ||
     !get_kb_item("SSL/Certificate/" + port)) continue;

  var der_cert = get_server_cert(port:port, encoding:"der");
  if(!der_cert) continue;

  var cert = parse_der_cert(cert:der_cert);
  if(!cert || !cert["tbsCertificate"] || !cert["tbsCertificate"]["extensions"]) continue;

  var extensions = cert["tbsCertificate"]["extensions"];
  foreach ext(extensions)
  {
    if(ext["extnID"] != EXTN_CERTIFICATE_COMMENT) continue;

    if("Automatically generated by Ncat" >< ext["extnValue"])
    {
       var report =  '\nThe following certificate:' +
       report += '\n\n    Subject: ' + format_dn(cert["tbsCertificate"]["subject"]) + '\n';
       report += '\nsent by the remote host has a comment attribute';
       report += '\nindicating that the service listening on port ' + port;
       report += '\nis an Ncat server:';
       report += '\n\n    ' + ext["extnValue"];

       security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
    }
  }
}