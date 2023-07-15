#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-01.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(121512);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id(
    "CVE-2018-18500",
    "CVE-2018-18501",
    "CVE-2018-18502",
    "CVE-2018-18503",
    "CVE-2018-18504",
    "CVE-2018-18505",
    "CVE-2018-18506"
  );
  script_bugtraq_id(106773, 106781);
  script_xref(name:"MFSA", value:"2019-01");

  script_name(english:"Mozilla Firefox < 65.0");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox installed on the remote Windows host is prior
to 65.0. It is, therefore, affected by multiple vulnerabilities as
referenced in the mfsa2019-01 advisory.

  - A use-after-free vulnerability can occur while parsing
    an HTML5 stream in concert with custom HTML elements.
    This results in the stream parser object being freed
    while still in use, leading to a potentially exploitable
    crash. (CVE-2018-18500)

  - When JavaScript is used to create and manipulate an
    audio buffer, a potentially exploitable crash may occur
    because of a compartment mismatch in some situations.
    (CVE-2018-18503)

  - A crash and out-of-bounds read can occur when the buffer
    of a texture client is freed while it is still in use
    during graphic operations. This results in a potentially
    exploitable crash and the possibility of reading from
    the memory of the freed buffers. (CVE-2018-18504)

  - An earlier fix for an Inter-process Communication (IPC)
    vulnerability, CVE-2011-3079, added authentication to
    communication between IPC endpoints and server parents
    during IPC process creation. This authentication is
    insufficient for channels created after the IPC process
    is started, leading to the authentication not being
    correctly applied to later channels. This could allow
    for a sandbox escape through IPC channels due to lack of
    message validation in the listener process.
    (CVE-2018-18505)

  - When proxy auto-detection is enabled, if a web server
    serves a Proxy Auto-Configuration (PAC) file or if a PAC
    file is loaded locally, this PAC file can specify that
    requests to the localhost are to be sent through the
    proxy to another server. This behavior is disallowed by
    default when a proxy is manually configured, but when
    enabled could allow for attacks on services and tools
    that bind to the localhost for networked behavior if
    they are accessed through browsing. (CVE-2018-18506)

  - Mozilla developers and community members Arthur Iakab,
    Christoph Diehl, Christian Holler, Kalel, Emilio Cobos
    lvarez, Cristina Coroiu, Noemi Erli, Natalia Csoregi,
    Julian Seward, Gary Kwong, Tyson Smith, Yaron Tausky,
    and Ronald Crane reported memory safety bugs present in
    Firefox 64. Some of these bugs showed evidence of memory
    corruption and we presume that with enough effort that
    some of these could be exploited to run arbitrary code.
    (CVE-2018-18502)

  - Mozilla developers and community members Alex Gaynor,
    Christoph Diehl, Steven Crane, Jason Kratzer, Gary
    Kwong, and Christian Holler reported memory safety bugs
    present in Firefox 64 and Firefox ESR 60.4. Some of
    these bugs showed evidence of memory corruption and we
    presume that with enough effort that some of these could
    be exploited to run arbitrary code. (CVE-2018-18501)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-01/");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1510114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1509442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1496413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1497749");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1087565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1503393");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1499426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1480090");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1472990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1514762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1501482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1505887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1508102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1508618");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1511580");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1493497");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1510145");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1516289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1506798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1512758");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1512450");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1517542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1513201");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1460619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1502871");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1516738");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1516514");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 65.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18502");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-18505");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'65.0', severity:SECURITY_HOLE);
