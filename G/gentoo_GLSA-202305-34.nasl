#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-34.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(176472);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/30");

  script_cve_id(
    "CVE-2020-28601",
    "CVE-2020-28602",
    "CVE-2020-28603",
    "CVE-2020-28604",
    "CVE-2020-28605",
    "CVE-2020-28606",
    "CVE-2020-28607",
    "CVE-2020-28608",
    "CVE-2020-28610",
    "CVE-2020-28611",
    "CVE-2020-28612",
    "CVE-2020-28613",
    "CVE-2020-28614",
    "CVE-2020-28615",
    "CVE-2020-28616",
    "CVE-2020-28617",
    "CVE-2020-28618",
    "CVE-2020-28619",
    "CVE-2020-28620",
    "CVE-2020-28621",
    "CVE-2020-28622",
    "CVE-2020-28623",
    "CVE-2020-28624",
    "CVE-2020-28625",
    "CVE-2020-28626",
    "CVE-2020-28627",
    "CVE-2020-28628",
    "CVE-2020-28629",
    "CVE-2020-28630",
    "CVE-2020-28631",
    "CVE-2020-28632",
    "CVE-2020-28633",
    "CVE-2020-28634",
    "CVE-2020-28635",
    "CVE-2020-28636",
    "CVE-2020-35628",
    "CVE-2020-35629",
    "CVE-2020-35630",
    "CVE-2020-35631",
    "CVE-2020-35632",
    "CVE-2020-35633",
    "CVE-2020-35634",
    "CVE-2020-35635",
    "CVE-2020-35636"
  );

  script_name(english:"GLSA-202305-34 : CGAL: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-34 (CGAL: Multiple Vulnerabilities)

  - A code execution vulnerability exists in the Nef polygon-parsing functionality of CGAL libcgal CGAL-5.1.1.
    An oob read vulnerability exists in Nef_2/PM_io_parser.h PM_io_parser::read_vertex() Face_of[] OOB read.
    An attacker can provide malicious input to trigger this vulnerability. (CVE-2020-28601)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_2/PM_io_parser.h
    PM_io_parser<PMDEC>::read_vertex() Halfedge_of[]. (CVE-2020-28602)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_2/PM_io_parser.h
    PM_io_parser<PMDEC>::read_hedge() e->set_prev(). (CVE-2020-28603)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_2/PM_io_parser.h
    PM_io_parser<PMDEC>::read_hedge() e->set_next(). (CVE-2020-28604)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read exists in Nef_2/PM_io_parser.h PM_io_parser<PMDEC>::read_hedge()
    e->set_vertex(). (CVE-2020-28605)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_2/PM_io_parser.h
    PM_io_parser<PMDEC>::read_hedge() e->set_face(). (CVE-2020-28606)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_2/PM_io_parser.h PM_io_parser<PMDEC>::read_face()
    set_halfedge(). (CVE-2020-28607)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_2/PM_io_parser.h PM_io_parser<PMDEC>::read_face()
    store_fc(). (CVE-2020-28608)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SM_io_parser.h
    SM_io_parser<Decorator_>::read_vertex() set_face(). (CVE-2020-28610)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SM_io_parser.h
    SM_io_parser<Decorator_>::read_vertex() set_first_out_edge(). (CVE-2020-28611)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_vertex() vh->svertices_begin(). (CVE-2020-28612)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_vertex() vh->svertices_last(). (CVE-2020-28613)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_vertex() vh->shalfedges_begin(). (CVE-2020-28614)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_vertex() vh->shalfedges_last(). (CVE-2020-28615)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_vertex() vh->sfaces_begin(). (CVE-2020-28616)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_vertex() vh->sfaces_last(). (CVE-2020-28617)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_vertex() vh->shalfloop(). (CVE-2020-28618)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h SNC_io_parser<EW>::read_edge()
    eh->twin(). (CVE-2020-28619)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h SNC_io_parser<EW>::read_edge()
    eh->center_vertex():. (CVE-2020-28620)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h SNC_io_parser<EW>::read_edge()
    eh->out_sedge(). (CVE-2020-28621)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h SNC_io_parser<EW>::read_edge()
    eh->incident_sface(). (CVE-2020-28622)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_facet() fh->twin(). (CVE-2020-28623)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_facet() fh->boundary_entry_objects SEdge_of. (CVE-2020-28624)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_facet() fh->boundary_entry_objects SLoop_of. (CVE-2020-28625)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_facet() fh->incident_volume(). (CVE-2020-28626)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_volume() ch->shell_entry_objects(). (CVE-2020-28627)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_volume() seh->twin(). (CVE-2020-28628)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_sedge() seh->sprev(). (CVE-2020-28629)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_sedge() seh->snext(). (CVE-2020-28630)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_sedge() seh->source(). (CVE-2020-28631)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_sedge() seh->incident_sface(). (CVE-2020-28632)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_sedge() seh->prev(). (CVE-2020-28633)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_sedge() seh->next(). (CVE-2020-28634)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_sedge() seh->facet(). (CVE-2020-28635)

  - A code execution vulnerability exists in the Nef polygon-parsing functionality of CGAL libcgal CGAL-5.1.1.
    An oob read vulnerability exists in Nef_S2/SNC_io_parser.h SNC_io_parser::read_sloop() slh->twin() An
    attacker can provide malicious input to trigger this vulnerability. (CVE-2020-28636)

  - A code execution vulnerability exists in the Nef polygon-parsing functionality of CGAL libcgal CGAL-5.1.1.
    An oob read vulnerability exists in Nef_S2/SNC_io_parser.h SNC_io_parser::read_sloop()
    slh->incident_sface. An attacker can provide malicious input to trigger this vulnerability.
    (CVE-2020-35628)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_sloop() slh->facet(). (CVE-2020-35629)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_sface() sfh->center_vertex(). (CVE-2020-35630)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_sface() SD.link_as_face_cycle(). (CVE-2020-35631)

  - Multiple code execution vulnerabilities exists in the Nef polygon-parsing functionality of CGAL libcgal
    CGAL-5.1.1. A specially crafted malformed file can lead to an out-of-bounds read and type confusion, which
    could lead to code execution. An attacker can provide malicious input to trigger any of these
    vulnerabilities. An oob read vulnerability exists in Nef_S2/SNC_io_parser.h
    SNC_io_parser<EW>::read_sface() sfh->boundary_entry_objects Edge_of. (CVE-2020-35632)

  - A code execution vulnerability exists in the Nef polygon-parsing functionality of CGAL libcgal CGAL-5.1.1.
    An oob read vulnerability exists in Nef_S2/SNC_io_parser.h SNC_io_parser<EW>::read_sface()
    store_sm_boundary_item() Edge_of.A specially crafted malformed file can lead to an out-of-bounds read and
    type confusion, which could lead to code execution. An attacker can provide malicious input to trigger
    this vulnerability. (CVE-2020-35633)

  - A code execution vulnerability exists in the Nef polygon-parsing functionality of CGAL libcgal CGAL-5.1.1.
    An oob read vulnerability exists in Nef_S2/SNC_io_parser.h SNC_io_parser<EW>::read_sface()
    sfh->boundary_entry_objects Sloop_of. A specially crafted malformed file can lead to an out-of-bounds read
    and type confusion, which could lead to code execution. An attacker can provide malicious input to trigger
    this vulnerability. (CVE-2020-35634)

  - A code execution vulnerability exists in the Nef polygon-parsing functionality of CGAL libcgal CGAL-5.1.1
    in Nef_S2/SNC_io_parser.h SNC_io_parser::read_sface() store_sm_boundary_item() Sloop_of OOB read. A
    specially crafted malformed file can lead to an out-of-bounds read and type confusion, which could lead to
    code execution. An attacker can provide malicious input to trigger this vulnerability. (CVE-2020-35635)

  - A code execution vulnerability exists in the Nef polygon-parsing functionality of CGAL libcgal CGAL-5.1.1
    in Nef_S2/SNC_io_parser.h SNC_io_parser::read_sface() sfh->volume() OOB read. A specially crafted
    malformed file can lead to an out-of-bounds read and type confusion, which could lead to code execution.
    An attacker can provide malicious input to trigger this vulnerability. (CVE-2020-35636)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-34");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=774261");
  script_set_attribute(attribute:"solution", value:
"All CGAL users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=sci-mathematics/cgal-5.4.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35636");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:cgal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'sci-mathematics/cgal',
    'unaffected' : make_list("ge 5.4.1"),
    'vulnerable' : make_list("lt 5.4.1")
  }
];

foreach var package( packages ) {
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
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'CGAL');
}
