#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1422.
#

include('compat.inc');

if (description)
{
  script_id(140096);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2012-6708",
    "CVE-2013-0269",
    "CVE-2015-9251",
    "CVE-2017-17742",
    "CVE-2019-15845",
    "CVE-2019-16201",
    "CVE-2019-16254",
    "CVE-2019-16255",
    "CVE-2020-10663"
  );
  script_bugtraq_id(
    57899,
    102792,
    103684,
    105658
  );
  script_xref(name:"ALAS", value:"2020-1422");

  script_name(english:"Amazon Linux AMI : ruby24 (ALAS-2020-1422)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS-2020-1422 advisory.

  - jQuery before 1.9.0 is vulnerable to Cross-site Scripting (XSS) attacks. The jQuery(strInput) function
    does not differentiate selectors from HTML in a reliable fashion. In vulnerable versions, jQuery
    determined whether the input was HTML by looking for the '<' character anywhere in the string, giving
    attackers more flexibility when attempting to construct a malicious payload. In fixed versions, jQuery
    only deems the input to be HTML if it explicitly starts with the '<' character, limiting exploitability
    only to attackers who can control the beginning of a string, which is far less common. (CVE-2012-6708)

  - The JSON gem before 1.5.5, 1.6.x before 1.6.8, and 1.7.x before 1.7.7 for Ruby allows remote attackers to
    cause a denial of service (resource consumption) or bypass the mass assignment protection mechanism via a
    crafted JSON document that triggers the creation of arbitrary Ruby symbols or certain internal objects, as
    demonstrated by conducting a SQL injection attack against Ruby on Rails, aka Unsafe Object Creation
    Vulnerability. (CVE-2013-0269)

  - jQuery before 3.0.0 is vulnerable to Cross-site Scripting (XSS) attacks when a cross-domain Ajax request
    is performed without the dataType option, causing text/javascript responses to be executed.
    (CVE-2015-9251)

  - Ruby before 2.2.10, 2.3.x before 2.3.7, 2.4.x before 2.4.4, 2.5.x before 2.5.1, and 2.6.0-preview1 allows
    an HTTP Response Splitting attack. An attacker can inject a crafted key and value into an HTTP response
    for the HTTP server of WEBrick. (CVE-2017-17742)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 mishandles path checking within
    File.fnmatch functions. (CVE-2019-15845)

  - WEBrick::HTTPAuth::DigestAuth in Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 has a
    regular expression Denial of Service cause by looping/backtracking. A victim must expose a WEBrick server
    that uses DigestAuth to the Internet or a untrusted network. (CVE-2019-16201)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 allows HTTP Response Splitting. If a
    program using WEBrick inserts untrusted input into the response header, an attacker can exploit it to
    insert a newline character to split a header, and inject malicious content to deceive clients. NOTE: this
    issue exists because of an incomplete fix for CVE-2017-17742, which addressed the CRLF vector, but did not
    address an isolated CR or an isolated LF. (CVE-2019-16254)

  - Ruby through 2.4.7, 2.5.x through 2.5.6, and 2.6.x through 2.6.4 allows code injection if the first
    argument (aka the command argument) to Shell#[] or Shell#test in lib/shell.rb is untrusted data. An
    attacker can exploit this to call an arbitrary Ruby method. (CVE-2019-16255)

  - The JSON gem through 2.2.0 for Ruby, as used in Ruby 2.4 through 2.4.9, 2.5 through 2.5.7, and 2.6 through
    2.6.5, has an Unsafe Object Creation Vulnerability. This is quite similar to CVE-2013-0269, but does not
    rely on poor garbage-collection behavior within Ruby. Specifically, use of JSON parsing methods can lead
    to creation of a malicious object within the interpreter, with adverse effects that are application-
    dependent. (CVE-2020-10663)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1422.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2012-6708");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2015-9251");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-15845");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16201");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16254");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-16255");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10663");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update ruby24' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0269");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-16255");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-minitest5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-net-telnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-power_assert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems24-devel");
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
    {'reference':'ruby24-2.4.10-2.12.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby24-2.4.10-2.12.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ruby24-debuginfo-2.4.10-2.12.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby24-debuginfo-2.4.10-2.12.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ruby24-devel-2.4.10-2.12.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby24-devel-2.4.10-2.12.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'ruby24-doc-2.4.10-2.12.amzn1', 'release':'ALA'},
    {'reference':'ruby24-irb-2.4.10-2.12.amzn1', 'release':'ALA'},
    {'reference':'ruby24-libs-2.4.10-2.12.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'ruby24-libs-2.4.10-2.12.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem24-bigdecimal-1.3.2-2.12.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem24-bigdecimal-1.3.2-2.12.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem24-did_you_mean-1.1.0-2.12.amzn1', 'release':'ALA'},
    {'reference':'rubygem24-io-console-0.4.6-2.12.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem24-io-console-0.4.6-2.12.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem24-json-2.0.4-2.12.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem24-json-2.0.4-2.12.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem24-minitest5-5.10.1-2.12.amzn1', 'release':'ALA'},
    {'reference':'rubygem24-net-telnet-0.1.1-2.12.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem24-net-telnet-0.1.1-2.12.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem24-power_assert-0.4.1-2.12.amzn1', 'release':'ALA'},
    {'reference':'rubygem24-psych-2.2.2-2.12.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem24-psych-2.2.2-2.12.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygem24-rdoc-5.0.1-2.12.amzn1', 'release':'ALA'},
    {'reference':'rubygem24-test-unit-3.2.3-2.12.amzn1', 'release':'ALA'},
    {'reference':'rubygem24-xmlrpc-0.2.1-2.12.amzn1', 'cpu':'i686', 'release':'ALA'},
    {'reference':'rubygem24-xmlrpc-0.2.1-2.12.amzn1', 'cpu':'x86_64', 'release':'ALA'},
    {'reference':'rubygems24-2.6.14.4-2.12.amzn1', 'release':'ALA'},
    {'reference':'rubygems24-devel-2.6.14.4-2.12.amzn1', 'release':'ALA'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby24 / ruby24-debuginfo / ruby24-devel / etc");
}
