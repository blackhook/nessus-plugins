#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-29.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(138589);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/20");

  script_cve_id(
    "CVE-2020-12402",
    "CVE-2020-12415",
    "CVE-2020-12416",
    "CVE-2020-12417",
    "CVE-2020-12418",
    "CVE-2020-12419",
    "CVE-2020-12420",
    "CVE-2020-12421",
    "CVE-2020-12422",
    "CVE-2020-12423",
    "CVE-2020-12424",
    "CVE-2020-12425",
    "CVE-2020-12426",
    "CVE-2020-15648"
  );
  script_xref(name:"MFSA", value:"2020-29");

  script_name(english:"Mozilla Thunderbird < 78.0");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 78.0. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2020-29 advisory.

  - When %2F was present in a manifest URL, Firefox's
    AppCache behavior may have become confused and allowed a
    manifest to be served from a subdirectory. This could
    cause the appcache to be used to service requests for
    the top level directory. This vulnerability affects
    Firefox < 78. (CVE-2020-12415)

  - A VideoStreamEncoder may have been freed in a race
    condition with VideoBroadcaster::AddOrUpdateSink,
    resulting in a use-after-free, memory corruption, and a
    potentially exploitable crash. This vulnerability
    affects Firefox < 78. (CVE-2020-12416)

  - Due to confusion about ValueTags on JavaScript Objects,
    an object may pass through the type barrier, resulting
    in memory corruption and a potentially exploitable
    crash. *Note: this issue only affects Firefox on ARM64
    platforms.* This vulnerability affects Firefox ESR <
    68.10, Firefox < 78, and Thunderbird < 68.10.0.
    (CVE-2020-12417)

  - Manipulating individual parts of a URL object could have
    caused an out-of-bounds read, leaking process memory to
    malicious JavaScript. This vulnerability affects Firefox
    ESR < 68.10, Firefox < 78, and Thunderbird < 68.10.0.
    (CVE-2020-12418)

  - When processing callbacks that occurred during window
    flushing in the parent process, the associated window
    may die; causing a use-after-free condition. This could
    have led to memory corruption and a potentially
    exploitable crash. This vulnerability affects Firefox
    ESR < 68.10, Firefox < 78, and Thunderbird < 68.10.0.
    (CVE-2020-12419)

  - When trying to connect to a STUN server, a race
    condition could have caused a use-after-free of a
    pointer, leading to memory corruption and a potentially
    exploitable crash. This vulnerability affects Firefox
    ESR < 68.10, Firefox < 78, and Thunderbird < 68.10.0.
    (CVE-2020-12420)

  - During RSA key generation, bignum implementations used a
    variation of the Binary Extended Euclidean Algorithm
    which entailed significantly input-dependent flow. This
    allowed an attacker able to perform electromagnetic-
    based side channel attacks to record traces leading to
    the recovery of the secret primes. *Note:* An unmodified
    Firefox browser does not generate RSA keys in normal
    operation and is not affected, but products built on top
    of it might. This vulnerability affects Firefox < 78.
    (CVE-2020-12402)

  - When performing add-on updates, certificate chains
    terminating in non-built-in-roots were rejected (even if
    they were legitimately added by an administrator.) This
    could have caused add-ons to become out-of-date silently
    without notification to the user. This vulnerability
    affects Firefox ESR < 68.10, Firefox < 78, and
    Thunderbird < 68.10.0. (CVE-2020-12421)

  - In non-standard configurations, a JPEG image created by
    JavaScript could have caused an internal variable to
    overflow, resulting in an out of bounds write, memory
    corruption, and a potentially exploitable crash. This
    vulnerability affects Firefox < 78. (CVE-2020-12422)

  - When the Windows DLL webauthn.dll was missing from the
    Operating System, and a malicious one was placed in a
    folder in the user's %PATH%, Firefox may have loaded the
    DLL, leading to arbitrary code execution. *Note: This
    issue only affects the Windows operating system; other
    operating systems are unaffected.* This vulnerability
    affects Firefox < 78. (CVE-2020-12423)

  - When constructing a permission prompt for WebRTC, a URI
    was supplied from the content process. This URI was
    untrusted, and could have been the URI of an origin that
    was previously granted permission; bypassing the prompt.
    This vulnerability affects Firefox < 78.
    (CVE-2020-12424)

  - Due to confusion processing a hyphen character in
    Date.parse(), a one-byte out of bounds read could have
    occurred, leading to potential information disclosure.
    This vulnerability affects Firefox < 78.
    (CVE-2020-12425)

  - Mozilla developers and community members reported memory
    safety bugs present in Firefox 77. Some of these bugs
    showed evidence of memory corruption and we presume that
    with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability
    affects Firefox < 78. (CVE-2020-12426)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-29/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 78.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12426");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'78.0', severity:SECURITY_HOLE);
