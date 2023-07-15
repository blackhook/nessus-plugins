#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156677);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/12");

  script_cve_id(
    "CVE-2021-22876",
    "CVE-2021-22890",
    "CVE-2021-22897",
    "CVE-2021-22898",
    "CVE-2021-22901"
  );
  script_xref(name:"JSA", value:"JSA11289");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA11289)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA11289 advisory.

  - curl 7.1.1 to and including 7.75.0 is vulnerable to an Exposure of Private Personal Information to an
    Unauthorized Actor by leaking credentials in the HTTP Referer: header. libcurl does not strip off user
    credentials from the URL when automatically populating the Referer: HTTP request header field in outgoing
    HTTP requests, and therefore risks leaking sensitive data to the server that is the target of the second
    HTTP request. (CVE-2021-22876)

  - curl 7.63.0 to and including 7.75.0 includes vulnerability that allows a malicious HTTPS proxy to MITM a
    connection due to bad handling of TLS 1.3 session tickets. When using a HTTPS proxy and TLS 1.3, libcurl
    can confuse session tickets arriving from the HTTPS proxy but work as if they arrived from the remote
    server and then wrongly short-cut the host handshake. When confusing the tickets, a HTTPS proxy can
    trick libcurl to use the wrong session ticket resume for the host and thereby circumvent the server TLS
    certificate check and make a MITM attack to be possible to perform unnoticed. Note that such a malicious
    HTTPS proxy needs to provide a certificate that curl will accept for the MITMed server for an attack to
    work - unless curl has been told to ignore the server certificate check. (CVE-2021-22890)

  - curl 7.61.0 through 7.76.1 suffers from exposure of data element to wrong session due to a mistake in the
    code for CURLOPT_SSL_CIPHER_LIST when libcurl is built to use the Schannel TLS library. The selected
    cipher set was stored in a single static variable in the library, which has the surprising side-effect
    that if an application sets up multiple concurrent transfers, the last one that sets the ciphers will
    accidentally control the set used by all transfers. In a worst-case scenario, this weakens transport
    security significantly. (CVE-2021-22897)

  - curl 7.7 through 7.76.1 suffers from an information disclosure when the `-t` command line option, known as
    `CURLOPT_TELNETOPTIONS` in libcurl, is used to send variable=content pairs to TELNET servers. Due to a
    flaw in the option parser for sending NEW_ENV variables, libcurl could be made to pass on uninitialized
    data from a stack based buffer to the server, resulting in potentially revealing sensitive internal
    information to the server using a clear-text network protocol. (CVE-2021-22898)

  - curl 7.75.0 through 7.76.1 suffers from a use-after-free vulnerability resulting in already freed memory
    being used when a TLS 1.3 session ticket arrives over a connection. A malicious server can use this in
    rare unfortunate circumstances to potentially reach remote code execution in the client. When libcurl at
    run-time sets up support for TLS 1.3 session tickets on a connection using OpenSSL, it stores pointers to
    the transfer in-memory object for later retrieval when a session ticket arrives. If the connection is used
    by multiple transfers (like with a reused HTTP/1.1 connection or multiplexed HTTP/2 connection) that first
    transfer object might be freed before the new session is established on that connection and then the
    function will access a memory buffer that might be freed. When using that memory, libcurl might even call
    a function pointer in the object, making it possible for a remote code execution if the server could
    somehow manage to get crafted memory content into the correct place in memory. (CVE-2021-22901)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11289");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11289");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22901");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'21.1', 'fixed_ver':'21.1R1'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R2'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
var report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
