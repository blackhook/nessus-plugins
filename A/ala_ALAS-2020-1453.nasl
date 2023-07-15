##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1453.
##

include('compat.inc');

if (description)
{
  script_id(142983);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2019-12528",
    "CVE-2020-8449",
    "CVE-2020-8450",
    "CVE-2020-15049",
    "CVE-2020-15810",
    "CVE-2020-15811",
    "CVE-2020-24606"
  );
  script_xref(name:"ALAS", value:"2020-1453");

  script_name(english:"Amazon Linux AMI : squid (ALAS-2020-1453)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS-2020-1453 advisory.

  - An issue was discovered in Squid before 4.10. It allows a crafted FTP server to trigger disclosure of
    sensitive information from heap memory, such as information associated with other users' sessions or non-
    Squid processes. (CVE-2019-12528)

  - An issue was discovered in http/ContentLengthInterpreter.cc in Squid before 4.12 and 5.x before 5.0.3. A
    Request Smuggling and Poisoning attack can succeed against the HTTP cache. The client sends an HTTP
    request with a Content-Length header containing +\ - or an uncommon shell whitespace character prefix
    to the length field-value. (CVE-2020-15049)

  - An issue was discovered in Squid before 4.13 and 5.x before 5.0.4. Due to incorrect data validation, HTTP
    Request Smuggling attacks may succeed against HTTP and HTTPS traffic. This leads to cache poisoning. This
    allows any client, including browser scripts, to bypass local security and poison the proxy cache and any
    downstream caches with content from an arbitrary source. When configured for relaxed header parsing (the
    default), Squid relays headers containing whitespace characters to upstream servers. When this occurs as a
    prefix to a Content-Length header, the frame length specified will be ignored by Squid (allowing for a
    conflicting length to be used from another Content-Length header) but relayed upstream. (CVE-2020-15810)

  - An issue was discovered in Squid before 4.13 and 5.x before 5.0.4. Due to incorrect data validation, HTTP
    Request Splitting attacks may succeed against HTTP and HTTPS traffic. This leads to cache poisoning. This
    allows any client, including browser scripts, to bypass local security and poison the browser cache and
    any downstream caches with content from an arbitrary source. Squid uses a string search instead of parsing
    the Transfer-Encoding header to find chunked encoding. This allows an attacker to hide a second request
    inside Transfer-Encoding: it is interpreted by Squid as chunked and split out into a second request
    delivered upstream. Squid will then deliver two distinct responses to the client, corrupting any
    downstream caches. (CVE-2020-15811)

  - Squid before 4.13 and 5.x before 5.0.4 allows a trusted peer to perform Denial of Service by consuming all
    available CPU cycles during handling of a crafted Cache Digest response message. This only occurs when
    cache_peer is used with the cache digests feature. The problem exists because peerDigestHandleReply()
    livelocking in peer_digest.cc mishandles EOF. (CVE-2020-24606)

  - An issue was discovered in Squid before 4.10. Due to incorrect input validation, it can interpret crafted
    HTTP requests in unexpected ways to access server resources prohibited by earlier security filters.
    (CVE-2020-8449)

  - An issue was discovered in Squid before 4.10. Due to incorrect buffer management, a remote client can
    cause a buffer overflow in a Squid instance acting as a reverse proxy. (CVE-2020-8450)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1453.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-12528");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-15049");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-15810");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-15811");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-24606");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8449");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-8450");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update squid' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8450");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-15049");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:squid-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:squid-migration-script");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'squid-3.5.20-17.41.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'squid-3.5.20-17.41.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'squid-debuginfo-3.5.20-17.41.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'squid-debuginfo-3.5.20-17.41.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'squid-migration-script-3.5.20-17.41.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'squid-migration-script-3.5.20-17.41.amzn1', 'cpu':'x86_64', 'release':'ALA'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid / squid-debuginfo / squid-migration-script");
}