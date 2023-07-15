#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(163840);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/01");

  script_cve_id(
    "CVE-2020-28366",
    "CVE-2020-28367",
    "CVE-2021-3114",
    "CVE-2021-3115",
    "CVE-2021-27918",
    "CVE-2021-27919",
    "CVE-2021-29923",
    "CVE-2021-31525",
    "CVE-2021-33195",
    "CVE-2021-33196",
    "CVE-2021-33197",
    "CVE-2021-33198",
    "CVE-2021-34558",
    "CVE-2021-36221",
    "CVE-2021-38297",
    "CVE-2021-41771",
    "CVE-2021-41772",
    "CVE-2021-44716",
    "CVE-2021-44717",
    "CVE-2022-1705",
    "CVE-2022-23772",
    "CVE-2022-23773",
    "CVE-2022-23806",
    "CVE-2022-24675",
    "CVE-2022-24921",
    "CVE-2022-27536",
    "CVE-2022-28131",
    "CVE-2022-28327",
    "CVE-2022-29526",
    "CVE-2022-30629",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-30635",
    "CVE-2022-32148",
    "CVE-2022-32189"
  );
  script_xref(name:"IAVB", value:"2022-B-0025-S");

  script_name(english:"GLSA-202208-02 : Go: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-02 (Go: Multiple Vulnerabilities)

  - Go before 1.14.12 and 1.15.x before 1.15.5 allows Code Injection. (CVE-2020-28366)

  - Go before 1.14.12 and 1.15.x before 1.15.5 allows Argument Injection. (CVE-2020-28367)

  - encoding/xml in Go before 1.15.9 and 1.16.x before 1.16.1 has an infinite loop if a custom TokenReader
    (for xml.NewTokenDecoder) returns EOF in the middle of an element. This can occur in the Decode,
    DecodeElement, or Skip method. (CVE-2021-27918)

  - archive/zip in Go 1.16.x before 1.16.1 allows attackers to cause a denial of service (panic) upon
    attempted use of the Reader.Open API for a ZIP archive in which ../ occurs at the beginning of any
    filename. (CVE-2021-27919)

  - Go before 1.17 does not properly consider extraneous zero characters at the beginning of an IP address
    octet, which (in some situations) allows attackers to bypass access control that is based on IP addresses,
    because of unexpected octal interpretation. This affects net.ParseIP and net.ParseCIDR. (CVE-2021-29923)

  - In Go before 1.14.14 and 1.15.x before 1.15.7, crypto/elliptic/p224.go can generate incorrect outputs,
    related to an underflow of the lowest limb during the final complete reduction in the P-224 field.
    (CVE-2021-3114)

  - Go before 1.14.14 and 1.15.x before 1.15.7 on Windows is vulnerable to Command Injection and remote code
    execution when using the go get command to fetch modules that make use of cgo (for example, cgo can
    execute a gcc program from an untrusted download). (CVE-2021-3115)

  - net/http in Go before 1.15.12 and 1.16.x before 1.16.4 allows remote attackers to cause a denial of
    service (panic) via a large header to ReadRequest or ReadResponse. Server, Transport, and Client can each
    be affected in some configurations. (CVE-2021-31525)

  - Go before 1.15.13 and 1.16.x before 1.16.5 has functions for DNS lookups that do not validate replies from
    DNS servers, and thus a return value may contain an unsafe injection (e.g., XSS) that does not conform to
    the RFC1035 format. (CVE-2021-33195)

  - In archive/zip in Go before 1.15.13 and 1.16.x before 1.16.5, a crafted file count (in an archive's
    header) can cause a NewReader or OpenReader panic. (CVE-2021-33196)

  - In Go before 1.15.13 and 1.16.x before 1.16.5, some configurations of ReverseProxy (from
    net/http/httputil) result in a situation where an attacker is able to drop arbitrary headers.
    (CVE-2021-33197)

  - In Go before 1.15.13 and 1.16.x before 1.16.5, there can be a panic for a large exponent to the
    math/big.Rat SetString or UnmarshalText method. (CVE-2021-33198)

  - The crypto/tls package of Go through 1.16.5 does not properly assert that the type of public key in an
    X.509 certificate matches the expected type when doing a RSA based key exchange, allowing a malicious TLS
    server to cause a TLS client to panic. (CVE-2021-34558)

  - Go before 1.15.15 and 1.16.x before 1.16.7 has a race condition that can lead to a net/http/httputil
    ReverseProxy panic upon an ErrAbortHandler abort. (CVE-2021-36221)

  - Go before 1.16.9 and 1.17.x before 1.17.2 has a Buffer Overflow via large arguments in a function
    invocation from a WASM module, when GOARCH=wasm GOOS=js is used. (CVE-2021-38297)

  - ImportedSymbols in debug/macho (for Open or OpenFat) in Go before 1.16.10 and 1.17.x before 1.17.3
    Accesses a Memory Location After the End of a Buffer, aka an out-of-bounds slice situation.
    (CVE-2021-41771)

  - Go before 1.16.10 and 1.17.x before 1.17.3 allows an archive/zip Reader.Open panic via a crafted ZIP
    archive containing an invalid name or an empty filename field. (CVE-2021-41772)

  - net/http in Go before 1.16.12 and 1.17.x before 1.17.5 allows uncontrolled memory consumption in the
    header canonicalization cache via HTTP/2 requests. (CVE-2021-44716)

  - Go before 1.16.12 and 1.17.x before 1.17.5 on UNIX allows write operations to an unintended file or
    unintended network connection as a consequence of erroneous closing of file descriptor 0 after file-
    descriptor exhaustion. (CVE-2021-44717)

  - Rat.SetString in math/big in Go before 1.16.14 and 1.17.x before 1.17.7 has an overflow that can lead to
    Uncontrolled Memory Consumption. (CVE-2022-23772)

  - cmd/go in Go before 1.16.14 and 1.17.x before 1.17.7 can misinterpret branch names that falsely appear to
    be version tags. This can lead to incorrect access control if an actor is supposed to be able to create
    branches but not tags. (CVE-2022-23773)

  - Curve.IsOnCurve in crypto/elliptic in Go before 1.16.14 and 1.17.x before 1.17.7 can incorrectly return
    true in situations with a big.Int value that is not a valid field element. (CVE-2022-23806)

  - encoding/pem in Go before 1.17.9 and 1.18.x before 1.18.1 has a Decode stack overflow via a large amount
    of PEM data. (CVE-2022-24675)

  - regexp.Compile in Go before 1.16.15 and 1.17.x before 1.17.8 allows stack exhaustion via a deeply nested
    expression. (CVE-2022-24921)

  - Certificate.Verify in crypto/x509 in Go 1.18.x before 1.18.1 can be caused to panic on macOS when
    presented with certain malformed certificates. This allows a remote TLS server to cause a TLS client to
    panic. (CVE-2022-27536)

  - The generic P-256 feature in crypto/elliptic in Go before 1.17.9 and 1.18.x before 1.18.1 allows a panic
    via long scalar input. (CVE-2022-28327)

  - Go before 1.17.10 and 1.18.x before 1.18.2 has Incorrect Privilege Assignment. When called with a non-zero
    flags parameter, the Faccessat function could incorrectly report that a file is accessible.
    (CVE-2022-29526)

  - golang: net/http: improper sanitization of Transfer-Encoding header (CVE-2022-1705)

  - golang: encoding/xml: stack exhaustion in Decoder.Skip (CVE-2022-28131)

  - Automatic update for grafana-8.5.6-1.fc37.  ##### **Changelog**  ``` * Wed Jun 29 2022 Andreas Gerstmayr
    <agerstmayr@redhat.com> 8.5.6-1 - update to 8.5.6 tagged upstream community sources, see CHANGELOG -
    updated license to AGPLv3 - place commented sample config file in /etc/grafana/grafana.ini - enable Go
    modules in build process - adapt Node.js bundling to yarn v3 and Zero Install feature * Sun Jun 19 2022
    Robert-Andr Mauchin <zebob.m@gmail.com> - 7.5.15-3 - Rebuilt for CVE-2022-1996, CVE-2022-24675,
    CVE-2022-28327, CVE-2022-27191,   CVE-2022-29526, CVE-2022-30629  ``` (CVE-2022-30629)

  - golang: io/fs: stack exhaustion in Glob (CVE-2022-30630)

  - golang: compress/gzip: stack exhaustion in Reader.Read (CVE-2022-30631)

  - golang: path/filepath: stack exhaustion in Glob (CVE-2022-30632)

  - golang: encoding/xml: stack exhaustion in Unmarshal (CVE-2022-30633)

  - golang: encoding/gob: stack exhaustion in Decoder.Decode (CVE-2022-30635)

  - golang: net/http/httputil: NewSingleHostReverseProxy - omit X-Forwarded-For not working (CVE-2022-32148)

  - The Go project reports: encoding/gob & math/big: decoding big.Float and             big.Rat can panic
    Decoding big.Float and big.Rat types can panic if the             encoded message is too short.
    (CVE-2022-32189)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=754210");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=766216");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=775326");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=788640");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=794784");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=802054");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=806659");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=807049");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=816912");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=821859");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=828655");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=833156");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=834635");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=838130");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=843644");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=849290");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=857822");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=862822");
  script_set_attribute(attribute:"solution", value:
"All Go users shoud upgrade to the latest version:            # emerge --sync           # emerge --ask --oneshot
--verbose >=dev-lang/go-1.18.5          In addition, users using Portage 3.0.9 or later should ensure that packages with
Go binaries have no vulnerable code statically linked into their binaries by rebuilding the @golang-rebuild set:
# emerge --ask --oneshot --verbose @golang-rebuild");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-38297");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:go");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "dev-lang/go",
    'unaffected' : make_list("ge 1.18.5"),
    'vulnerable' : make_list("lt 1.18.5")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Go");
}
