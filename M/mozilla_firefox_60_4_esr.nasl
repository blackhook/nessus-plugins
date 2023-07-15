#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2018-30.
# The text itself is copyright (C) Mozilla Foundation.


include("compat.inc");

if (description)
{
  script_id(119606);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2018-12405",
    "CVE-2018-17466",
    "CVE-2018-18492",
    "CVE-2018-18493",
    "CVE-2018-18494",
    "CVE-2018-18498"
  );
  script_xref(name:"MFSA", value:"2018-30");

  script_name(english:"Mozilla Firefox ESR < 60.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox ESR.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote Windows
host is prior to 60.4. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2018-30 advisory.

  - Mozilla developers and community members Christian
    Holler, Diego Calleja, Andrew McCreight, Jon Coppeard,
    Jed Davis, Natalia Csoregi, Nicolas B. Pierron, and
    Tyson Smith reported memory safety bugs present in
    Firefox 63 and Firefox ESR 60.3. Some of these bugs
    showed evidence of memory corruption and we presume that
    with enough effort that some of these could be exploited
    to run arbitrary code. (CVE-2018-12405)

  - A buffer overflow and out-of-bounds read can occur in
    TextureStorage11 within the ANGLE graphics
    library, used for WebGL content. This results in a
    potentially exploitable crash. (CVE-2018-17466)

  - A use-after-free vulnerability can occur after deleting
    a selection element due to a weak reference to the
    select element in the options
    collection. This results in a potentially exploitable
    crash. (CVE-2018-18492)

  - A buffer overflow can occur in the Skia library during
    buffer offset calculations with hardware accelerated
    canvas 2D actions due to the use of 32-bit calculations
    instead of 64-bit. This results in a potentially
    exploitable crash. (CVE-2018-18493)

  - A same-origin policy violation allowing the theft of
    cross-origin URL entries when using the Javascript
    location property to cause a redirection to
    another site using
    performance.getEntries(). This is a same-
    origin policy violation and could allow for data theft.
    (CVE-2018-18494)

  - A potential vulnerability leading to an integer overflow
    can occur during buffer size calculations for images
    when a raw value is used instead of the checked value.
    This leads to a possible out-of-bounds write.
    (CVE-2018-18498)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-30/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1488295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1499861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1504452");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1487964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1500011");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1494752");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1498765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1503326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1505181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1500759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1504365");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1506640");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1503082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1502013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1510471");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 60.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18498");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'60.4', severity:SECURITY_HOLE);
