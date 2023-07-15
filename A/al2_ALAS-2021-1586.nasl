##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2021-1586.
##

include('compat.inc');

if (description)
{
  script_id(144798);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/07");

  script_cve_id(
    "CVE-2020-16012",
    "CVE-2020-16042",
    "CVE-2020-26951",
    "CVE-2020-26953",
    "CVE-2020-26956",
    "CVE-2020-26958",
    "CVE-2020-26959",
    "CVE-2020-26960",
    "CVE-2020-26961",
    "CVE-2020-26965",
    "CVE-2020-26968",
    "CVE-2020-26971",
    "CVE-2020-26973",
    "CVE-2020-26974",
    "CVE-2020-26978",
    "CVE-2020-35111",
    "CVE-2020-35113"
  );
  script_xref(name:"ALAS", value:"2021-1586");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2021-1586)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2021-1586 advisory.

  - A parsing and event loading mismatch in Firefox's SVG code could have allowed load events to fire, even
    after sanitization. An attacker already capable of exploiting an XSS vulnerability in privileged internal
    pages could have used this attack to bypass our built-in sanitizer. This vulnerability affects Firefox <
    83, Firefox ESR < 78.5, and Thunderbird < 78.5. (CVE-2020-26951)

  - It was possible to cause the browser to enter fullscreen mode without displaying the security UI; thus
    making it possible to attempt a phishing attack or otherwise confuse the user. This vulnerability affects
    Firefox < 83, Firefox ESR < 78.5, and Thunderbird < 78.5. (CVE-2020-26953)

  - In some cases, removing HTML elements during sanitization would keep existing SVG event handlers and
    therefore lead to XSS. This vulnerability affects Firefox < 83, Firefox ESR < 78.5, and Thunderbird <
    78.5. (CVE-2020-26956)

  - Firefox did not block execution of scripts with incorrect MIME types when the response was intercepted and
    cached through a ServiceWorker. This could lead to a cross-site script inclusion vulnerability, or a
    Content Security Policy bypass. This vulnerability affects Firefox < 83, Firefox ESR < 78.5, and
    Thunderbird < 78.5. (CVE-2020-26958)

  - During browser shutdown, reference decrementing could have occured on a previously freed object, resulting
    in a use-after-free, memory corruption, and a potentially exploitable crash. This vulnerability affects
    Firefox < 83, Firefox ESR < 78.5, and Thunderbird < 78.5. (CVE-2020-26959)

  - If the Compact() method was called on an nsTArray, the array could have been reallocated without updating
    other pointers, leading to a potential use-after-free and exploitable crash. This vulnerability affects
    Firefox < 83, Firefox ESR < 78.5, and Thunderbird < 78.5. (CVE-2020-26960)

  - When DNS over HTTPS is in use, it intentionally filters RFC1918 and related IP ranges from the responses
    as these do not make sense coming from a DoH resolver. However when an IPv4 address was mapped through
    IPv6, these addresses were erroneously let through, leading to a potential DNS Rebinding attack. This
    vulnerability affects Firefox < 83, Firefox ESR < 78.5, and Thunderbird < 78.5. (CVE-2020-26961)

  - Some websites have a feature Show Password where clicking a button will change a password field into a
    textbook field, revealing the typed password. If, when using a software keyboard that remembers user
    input, a user typed their password and used that feature, the type of the password field was changed,
    resulting in a keyboard layout change and the possibility for the software keyboard to remember the typed
    password. This vulnerability affects Firefox < 83, Firefox ESR < 78.5, and Thunderbird < 78.5.
    (CVE-2020-26965)

  - Mozilla developers reported memory safety bugs present in Firefox 82 and Firefox ESR 78.4. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 83, Firefox ESR < 78.5, and
    Thunderbird < 78.5. (CVE-2020-26968)

  - Certain blit values provided by the user were not properly constrained leading to a heap buffer overflow
    on some video drivers. This vulnerability affects Firefox < 84, Thunderbird < 78.6, and Firefox ESR <
    78.6. (CVE-2020-26971)

  - Certain input to the CSS Sanitizer confused it, resulting in incorrect components being removed. This
    could have been used as a sanitizer bypass. This vulnerability affects Firefox < 84, Thunderbird < 78.6,
    and Firefox ESR < 78.6. (CVE-2020-26973)

  - When flex-basis was used on a table wrapper, a StyleGenericFlexBasis object could have been incorrectly
    cast to the wrong type. This resulted in a heap user-after-free, memory corruption, and a potentially
    exploitable crash. This vulnerability affects Firefox < 84, Thunderbird < 78.6, and Firefox ESR < 78.6.
    (CVE-2020-26974)

  - Using techniques that built on the slipstream research, a malicious webpage could have exposed both an
    internal network's hosts as well as services running on the user's local machine. This vulnerability
    affects Firefox < 84, Thunderbird < 78.6, and Firefox ESR < 78.6. (CVE-2020-26978)

  - When an extension with the proxy permission registered to receive , the proxy.onRequest callback
    was not triggered for view-source URLs. While web content cannot navigate to such URLs, a user opening
    View Source could have inadvertently leaked their IP address. This vulnerability affects Firefox < 84,
    Thunderbird < 78.6, and Firefox ESR < 78.6. (CVE-2020-35111)

  - Mozilla developers reported memory safety bugs present in Firefox 83 and Firefox ESR 78.5. Some of these
    bugs showed evidence of memory corruption and we presume that with enough effort some of these could have
    been exploited to run arbitrary code. This vulnerability affects Firefox < 84, Thunderbird < 78.6, and
    Firefox ESR < 78.6. (CVE-2020-35113)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2021-1586.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-16012");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-16042");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26951");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26953");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26956");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26958");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26959");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26960");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26961");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26965");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26968");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26971");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26973");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26974");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-26978");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-35111");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-35113");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update thunderbird' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26968");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'thunderbird-78.6.0-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'allowmaj':TRUE},
    {'reference':'thunderbird-78.6.0-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-78.6.0-1.amzn2', 'cpu':'aarch64', 'release':'AL2', 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-78.6.0-1.amzn2', 'cpu':'x86_64', 'release':'AL2', 'allowmaj':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}