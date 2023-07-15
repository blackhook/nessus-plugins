##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148681);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2016-10009",
    "CVE-2016-10010",
    "CVE-2016-10011",
    "CVE-2016-10012",
    "CVE-2016-10708"
  );
  script_xref(name:"JSA", value:"JSA11169");

  script_name(english:"Juniper Junos OS Multiple Vulnerabilities (JSA11169)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by multiple vulnerabilities as referenced in the
JSA11169 advisory.

  - Untrusted search path vulnerability in ssh-agent.c in ssh-agent in OpenSSH before 7.4 allows remote
    attackers to execute arbitrary local PKCS#11 modules by leveraging control over a forwarded agent-socket.
    (CVE-2016-10009)

  - sshd in OpenSSH before 7.4, when privilege separation is not used, creates forwarded Unix-domain sockets
    as root, which might allow local users to gain privileges via unspecified vectors, related to
    serverloop.c. (CVE-2016-10010)

  - authfile.c in sshd in OpenSSH before 7.4 does not properly consider the effects of realloc on buffer
    contents, which might allow local users to obtain sensitive private-key information by leveraging access
    to a privilege-separated child process. (CVE-2016-10011)

  - The shared memory manager (associated with pre-authentication compression) in sshd in OpenSSH before 7.4
    does not ensure that a bounds check is enforced by all compilers, which might allows local users to gain
    privileges by leveraging access to a sandboxed privilege-separation process, related to the m_zback and
    m_zlib data structures. (CVE-2016-10012)

  - sshd in OpenSSH before 7.4 allows remote attackers to cause a denial of service (NULL pointer dereference
    and daemon crash) via an out-of-sequence NEWKEYS message, as demonstrated by Honggfuzz, related to kex.c
    and packet.c. (CVE-2016-10708)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11169");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11169");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10009");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-10012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');


ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

vuln_ranges = [
  {'min_ver':'17.2', 'fixed_ver':'17.2R3-S4'},
  {'min_ver':'17.3', 'fixed_ver':'17.3R3-S8'},
  {'min_ver':'17.4', 'fixed_ver':'17.4R2-S9'},
  {'min_ver':'18.1', 'fixed_ver':'18.1R3-S13'},
  {'min_ver':'18.2', 'fixed_ver':'18.2R2-S7'},
  {'min_ver':'18.3', 'fixed_ver':'18.3R1-S7'},
  {'min_ver':'18.4', 'fixed_ver':'18.4R1-S7'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R1-S4'}
];

fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
