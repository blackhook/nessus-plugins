#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2022-1900.
##

include('compat.inc');

if (description)
{
  script_id(168453);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-3032",
    "CVE-2022-3033",
    "CVE-2022-3034",
    "CVE-2022-36059",
    "CVE-2022-39236",
    "CVE-2022-39249",
    "CVE-2022-39250",
    "CVE-2022-39251",
    "CVE-2022-40674",
    "CVE-2022-40956",
    "CVE-2022-40957",
    "CVE-2022-40958",
    "CVE-2022-40959",
    "CVE-2022-40960",
    "CVE-2022-40962",
    "CVE-2022-42927",
    "CVE-2022-42928",
    "CVE-2022-42929",
    "CVE-2022-42932"
  );
  script_xref(name:"IAVA", value:"2022-A-0444-S");
  script_xref(name:"IAVA", value:"2022-A-0349-S");
  script_xref(name:"IAVA", value:"2022-A-0386-S");
  script_xref(name:"IAVA", value:"2022-A-0393-S");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2022-1900)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of thunderbird installed on the remote host is prior to 102.4.0-1. It is, therefore, affected by multiple
vulnerabilities as referenced in the ALAS2-2022-1900 advisory.

  - Matrix Javascript SDK is the Matrix Client-Server SDK for JavaScript. Starting with version 17.1.0-rc.1,
    improperly formed beacon events can disrupt or impede the matrix-js-sdk from functioning properly,
    potentially impacting the consumer's ability to process data safely. Note that the matrix-js-sdk can
    appear to be operating normally but be excluding or corrupting runtime data presented to the consumer.
    This is patched in matrix-js-sdk v19.7.0. Redacting applicable events, waiting for the sync processor to
    store data, and restarting the client are possible workarounds. Alternatively, redacting the applicable
    events and clearing all storage will fix the further perceived issues. Downgrading to an unaffected
    version, noting that such a version may be subject to other vulnerabilities, will additionally resolve the
    issue. (CVE-2022-39236)

  - Matrix Javascript SDK is the Matrix Client-Server SDK for JavaScript. Prior to version 19.7.0, an attacker
    cooperating with a malicious homeserver can construct messages appearing to have come from another person.
    Such messages will be marked with a grey shield on some platforms, but this may be missing in others. This
    attack is possible due to the matrix-js-sdk implementing a too permissive key forwarding strategy on the
    receiving end. Starting with version 19.7.0, the default policy for accepting key forwards has been made
    more strict in the matrix-js-sdk. matrix-js-sdk will now only accept forwarded keys in response to
    previously issued requests and only from own, verified devices. The SDK now sets a `trusted` flag on the
    decrypted message upon decryption, based on whether the key used to decrypt the message was received from
    a trusted source. Clients need to ensure that messages decrypted with a key with `trusted = false` are
    decorated appropriately, for example, by showing a warning for such messages. This attack requires
    coordination between a malicious homeserver and an attacker, and those who trust your homeservers do not
    need a workaround. (CVE-2022-39249)

  - Matrix JavaScript SDK is the Matrix Client-Server software development kit (SDK) for JavaScript. Prior to
    version 19.7.0, an attacker cooperating with a malicious homeserver could interfere with the verification
    flow between two users, injecting its own cross-signing user identity in place of one of the users'
    identities. This would lead to the other device trusting/verifying the user identity under the control of
    the homeserver instead of the intended one. The vulnerability is a bug in the matrix-js-sdk, caused by
    checking and signing user identities and devices in two separate steps, and inadequately fixing the keys
    to be signed between those steps. Even though the attack is partly made possible due to the design
    decision of treating cross-signing user identities as Matrix devices on the server side (with their device
    ID set to the public part of the user identity key), no other examined implementations were vulnerable.
    Starting with version 19.7.0, the matrix-js-sdk has been modified to double check that the key signed is
    the one that was verified instead of just referencing the key by ID. An additional check has been made to
    report an error when one of the device ID matches a cross-signing key. As this attack requires
    coordination between a malicious homeserver and an attacker, those who trust their homeservers do not need
    a particular workaround. (CVE-2022-39250)

  - Matrix Javascript SDK is the Matrix Client-Server SDK for JavaScript. Prior to version 19.7.0, an attacker
    cooperating with a malicious homeserver can construct messages that legitimately appear to have come from
    another person, without any indication such as a grey shield. Additionally, a sophisticated attacker
    cooperating with a malicious homeserver could employ this vulnerability to perform a targeted attack in
    order to send fake to-device messages appearing to originate from another user. This can allow, for
    example, to inject the key backup secret during a self-verification, to make a targeted device start using
    a malicious key backup spoofed by the homeserver. These attacks are possible due to a protocol confusion
    vulnerability that accepts to-device messages encrypted with Megolm instead of Olm. Starting with version
    19.7.0, matrix-js-sdk has been modified to only accept Olm-encrypted to-device messages. Out of caution,
    several other checks have been audited or added. This attack requires coordination between a malicious
    home server and an attacker, so those who trust their home servers do not need a workaround.
    (CVE-2022-39251)

  - libexpat before 2.4.9 has a use-after-free in the doContent function in xmlparse.c. (CVE-2022-40674)

  - Mozilla: Remote content specified in an HTML document that was nested inside an iframe's srcdoc attribute
    was not blocked (CVE-2022-3032)

  - Mozilla: Leaking of sensitive information when composing a response to an HTML email with a META refresh
    tag (CVE-2022-3033)

  - Mozilla: An iframe element in an HTML email could trigger a network request (CVE-2022-3034)

  - Mozilla: Matrix SDK bundled with Thunderbird vulnerable to denial-of-service attack (CVE-2022-36059)

  - When injecting an HTML base element, some requests would ignore the CSP's base-uri settings and accept the
    injected element's base instead.  (CVE-2022-40956)

  - Inconsistent data in instruction and data cache when creating wasm code could lead to a potentially
    exploitable crash. This bug only affects Firefox on ARM64 platforms.  (CVE-2022-40957)

  - By injecting a cookie with certain special characters, an attacker on a shared subdomain which is not a
    secure context could set and thus overwrite cookies from a secure context, leading to session fixation and
    other attacks.  (CVE-2022-40958)

  - During iframe navigation, certain pages did not have their FeaturePolicy fully initialized leading to a
    bypass that leaked device permissions into untrusted subdocuments.  (CVE-2022-40959)

  - Concurrent use of the URL parser with non-UTF-8 data was not thread-safe. This could lead to a use-after-
    free causing a potentially exploitable crash.  (CVE-2022-40960)

  - Mozilla developers Nika Layzell, Timothy Nikkel, Sebastian Hengst, Andreas Pehrson, and the Mozilla
    Fuzzing Team reported memory safety bugs present in Firefox 104 and Firefox ESR 102.2. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code.  (CVE-2022-40962)

  - A same-origin policy violation could have allowed the theft of cross-origin URL entries, leaking the
    result of a redirect, via <code>performance.getEntries()</code>.  (CVE-2022-42927)

  - Certain types of allocations were missing annotations that, if the Garbage Collector was in a specific
    state, could have lead to memory corruption and a potentially exploitable crash.  (CVE-2022-42928)

  - If a website called <code>window.print()</code> in a particular way, it could cause a denial of service of
    the browser, which may persist beyond browser restart depending on the user's session restore settings.
    (CVE-2022-42929)

  - Mozilla developers Ashley Hale and the Mozilla Fuzzing Team reported memory safety bugs present in
    Thunderbird 102.3. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code.  (CVE-2022-42932)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2022-1900.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3032.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3033.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-3034.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-36059.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-39236.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-39249.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-39250.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-39251.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40674.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40956.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40957.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40958.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40959.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40960.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-40962.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42927.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42928.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42929.html");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/cve/html/CVE-2022-42932.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update thunderbird' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'thunderbird-102.4.0-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-102.4.0-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-102.4.0-1.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-102.4.0-1.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}