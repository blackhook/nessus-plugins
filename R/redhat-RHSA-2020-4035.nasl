##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4035. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143094);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2019-6237",
    "CVE-2019-6251",
    "CVE-2019-8506",
    "CVE-2019-8524",
    "CVE-2019-8535",
    "CVE-2019-8536",
    "CVE-2019-8544",
    "CVE-2019-8551",
    "CVE-2019-8558",
    "CVE-2019-8559",
    "CVE-2019-8563",
    "CVE-2019-8571",
    "CVE-2019-8583",
    "CVE-2019-8584",
    "CVE-2019-8586",
    "CVE-2019-8587",
    "CVE-2019-8594",
    "CVE-2019-8595",
    "CVE-2019-8596",
    "CVE-2019-8597",
    "CVE-2019-8601",
    "CVE-2019-8607",
    "CVE-2019-8608",
    "CVE-2019-8609",
    "CVE-2019-8610",
    "CVE-2019-8611",
    "CVE-2019-8615",
    "CVE-2019-8619",
    "CVE-2019-8622",
    "CVE-2019-8623",
    "CVE-2019-8625",
    "CVE-2019-8644",
    "CVE-2019-8649",
    "CVE-2019-8658",
    "CVE-2019-8666",
    "CVE-2019-8669",
    "CVE-2019-8671",
    "CVE-2019-8672",
    "CVE-2019-8673",
    "CVE-2019-8674",
    "CVE-2019-8676",
    "CVE-2019-8677",
    "CVE-2019-8678",
    "CVE-2019-8679",
    "CVE-2019-8680",
    "CVE-2019-8681",
    "CVE-2019-8683",
    "CVE-2019-8684",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8688",
    "CVE-2019-8689",
    "CVE-2019-8690",
    "CVE-2019-8707",
    "CVE-2019-8710",
    "CVE-2019-8719",
    "CVE-2019-8720",
    "CVE-2019-8726",
    "CVE-2019-8733",
    "CVE-2019-8735",
    "CVE-2019-8743",
    "CVE-2019-8763",
    "CVE-2019-8764",
    "CVE-2019-8765",
    "CVE-2019-8766",
    "CVE-2019-8768",
    "CVE-2019-8769",
    "CVE-2019-8771",
    "CVE-2019-8782",
    "CVE-2019-8783",
    "CVE-2019-8808",
    "CVE-2019-8811",
    "CVE-2019-8812",
    "CVE-2019-8813",
    "CVE-2019-8814",
    "CVE-2019-8815",
    "CVE-2019-8816",
    "CVE-2019-8819",
    "CVE-2019-8820",
    "CVE-2019-8821",
    "CVE-2019-8822",
    "CVE-2019-8823",
    "CVE-2019-8835",
    "CVE-2019-8844",
    "CVE-2019-8846",
    "CVE-2019-11070",
    "CVE-2020-3862",
    "CVE-2020-3864",
    "CVE-2020-3865",
    "CVE-2020-3867",
    "CVE-2020-3868",
    "CVE-2020-3885",
    "CVE-2020-3894",
    "CVE-2020-3895",
    "CVE-2020-3897",
    "CVE-2020-3899",
    "CVE-2020-3900",
    "CVE-2020-3901",
    "CVE-2020-3902",
    "CVE-2020-10018",
    "CVE-2020-11793",
    "CVE-2021-30666",
    "CVE-2021-30761",
    "CVE-2021-30762"
  );
  script_bugtraq_id(
    109328,
    109329,
    108497,
    108566
  );
  script_xref(name:"RHSA", value:"2020:4035");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/25");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"RHEL 7 : webkitgtk4 (RHSA-2020:4035)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4035 advisory.

  - webkitgtk: HTTP proxy setting deanonymization information disclosure (CVE-2019-11070)

  - webkitgtk: Multiple memory corruption issues leading to arbitrary code execution (CVE-2019-6237,
    CVE-2019-8571, CVE-2019-8583, CVE-2019-8584, CVE-2019-8586, CVE-2019-8587, CVE-2019-8594, CVE-2019-8595,
    CVE-2019-8596, CVE-2019-8597, CVE-2019-8601, CVE-2019-8608, CVE-2019-8609, CVE-2019-8610, CVE-2019-8611,
    CVE-2019-8615, CVE-2019-8619, CVE-2019-8622, CVE-2019-8623, CVE-2019-8644, CVE-2019-8666, CVE-2019-8669,
    CVE-2019-8671, CVE-2019-8672, CVE-2019-8673, CVE-2019-8676, CVE-2019-8677, CVE-2019-8678, CVE-2019-8679,
    CVE-2019-8680, CVE-2019-8681, CVE-2019-8683, CVE-2019-8684, CVE-2019-8686, CVE-2019-8687, CVE-2019-8688,
    CVE-2019-8689, CVE-2019-8707, CVE-2019-8710, CVE-2019-8720, CVE-2019-8726, CVE-2019-8733, CVE-2019-8735,
    CVE-2019-8763, CVE-2019-8765, CVE-2019-8766, CVE-2019-8782, CVE-2019-8783, CVE-2019-8808, CVE-2019-8811,
    CVE-2019-8812, CVE-2019-8814, CVE-2019-8815, CVE-2019-8816, CVE-2019-8819, CVE-2019-8820, CVE-2019-8821,
    CVE-2019-8822, CVE-2019-8823, CVE-2020-3868)

  - webkitgtk: processing maliciously crafted web content lead to URI spoofing (CVE-2019-6251)

  - webkitgtk: malicous web content leads to arbitrary code execution (CVE-2019-8506)

  - webkitgtk: malicious web content leads to arbitrary code execution (CVE-2019-8524, CVE-2019-8559,
    CVE-2019-8563)

  - webkitgtk: malicious crafted web content leads to arbitrary code execution (CVE-2019-8535, CVE-2019-8536,
    CVE-2019-8558)

  - webkitgtk: malicious crafted web content leads to arbitrary we content (CVE-2019-8544)

  - webkitgtk: malicious web content leads to cross site scripting (CVE-2019-8551)

  - webkitgtk: Out-of-bounds read leading to memory disclosure (CVE-2019-8607)

  - webkitgtk: Incorrect state management leading to universal cross-site scripting (CVE-2019-8625,
    CVE-2019-8649, CVE-2019-8658, CVE-2019-8674, CVE-2019-8690, CVE-2019-8719, CVE-2019-8813, CVE-2020-3867)

  - webkitgtk: Multiple memory corruption  issues leading to arbitrary code execution (CVE-2019-8743)

  - webkitgtk: Incorrect state  management leading to universal cross-site scripting (CVE-2019-8764)

  - webkitgtk: Browsing history could not be deleted (CVE-2019-8768)

  - webkitgtk: Websites could reveal browsing history (CVE-2019-8769)

  - webkitgtk: Violation of iframe sandboxing policy (CVE-2019-8771)

  - webkitgtk: Processing maliciously crafted web content may lead to arbitrary code execution (CVE-2019-8835,
    CVE-2019-8844)

  - webkitgtk: Use after free issue may lead to remote code execution (CVE-2019-8846)

  - webkitgtk: Use-after-free issue in accessibility/AXObjectCache.cpp (CVE-2020-10018)

  - webkitgtk: use-after-free via crafted web content (CVE-2020-11793)

  - webkitgtk: Denial of service via incorrect memory handling (CVE-2020-3862)

  - webkitgtk: Non-unique security origin for DOM object contexts (CVE-2020-3864)

  - webkitgtk: Incorrect security check for a top-level DOM object context (CVE-2020-3865)

  - webkitgtk: Incorrect processing of file URLs (CVE-2020-3885)

  - webkitgtk: Race condition allows reading of restricted memory (CVE-2020-3894)

  - webkitgtk: Memory corruption triggered by a malicious web content (CVE-2020-3895)

  - webkitgtk: Type confusion leading to arbitrary code execution (CVE-2020-3897, CVE-2020-3901)

  - webkitgtk: Memory consumption issue leading to arbitrary code execution (CVE-2020-3899)

  - webkitgtk: Memory corruption  triggered by a malicious web content (CVE-2020-3900)

  - webkitgtk: Input validation issue leading to cross-site script attack (CVE-2020-3902)

  - webkitgtk: Buffer overflow leading to arbitrary code execution (CVE-2021-30666)

  - webkitgtk: Memory corruption leading to arbitrary code execution (CVE-2021-30761)

  - webkitgtk: Use-after-free leading to arbitrary code execution (CVE-2021-30762)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-6237");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-6251");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8506");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8524");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8535");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8536");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8544");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8551");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8558");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8559");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8563");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8571");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8583");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8584");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8586");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8587");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8594");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8595");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8596");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8597");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8601");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8607");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8608");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8609");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8610");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8611");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8615");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8619");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8622");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8623");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8625");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8644");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8649");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8658");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8666");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8669");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8671");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8672");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8673");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8674");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8676");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8677");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8678");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8679");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8680");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8681");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8683");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8684");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8686");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8687");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8688");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8689");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8690");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8707");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8710");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8719");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8720");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8726");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8733");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8735");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8743");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8763");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8764");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8765");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8766");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8768");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8769");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8771");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8782");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8783");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8808");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8811");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8812");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8813");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8814");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8815");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8816");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8819");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8820");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8821");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8822");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8823");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8835");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8844");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-8846");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-11070");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3862");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3864");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3865");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3867");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3868");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3885");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3894");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3895");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3897");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3899");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3900");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3901");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-3902");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-10018");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11793");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30666");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30761");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2021-30762");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4035");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1667409");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1709289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1719199");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1719209");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1719210");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1719213");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1719224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1719231");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1719235");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1719237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1719238");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1811721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1816686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1829369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876463");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876470");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876472");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876518");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876523");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876542");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876543");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876545");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876548");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876549");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876555");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876590");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876592");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876593");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876615");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876616");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876632");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876634");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876644");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876646");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876647");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876650");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876652");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876653");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876655");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876656");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876881");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876883");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876887");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876891");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876892");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876895");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876897");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1876900");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1877045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1877046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1877047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1877048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1877049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1986898");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3899");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10018");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 79, 94, 119, 200, 400, 416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkitgtk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkitgtk4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkitgtk4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkitgtk4-jsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkitgtk4-jsc-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/debug',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/optional/os',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/os',
      'content/dist/rhel-alt/server/7/7Server/armv8-a/aarch64/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/os',
      'content/dist/rhel/client/7/7Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/oracle-java-rm/os',
      'content/dist/rhel/client/7/7Client/x86_64/os',
      'content/dist/rhel/client/7/7Client/x86_64/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/os',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/oracle-java-rm/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/os',
      'content/dist/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/debug',
      'content/dist/rhel/power/7/7Server/ppc64/sap/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/debug',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/os',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/os',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/debug',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/os',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/optional/debug',
      'content/dist/rhel/server/7/7Server/x86_64/optional/os',
      'content/dist/rhel/server/7/7Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/oracle-java-rm/os',
      'content/dist/rhel/server/7/7Server/x86_64/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rt/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rt/os',
      'content/dist/rhel/server/7/7Server/x86_64/rt/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/os',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/os',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/os',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/os',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/oracle-java-rm/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/os',
      'content/fastrack/rhel/client/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/os',
      'content/fastrack/rhel/client/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/os',
      'content/fastrack/rhel/computenode/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/os',
      'content/fastrack/rhel/computenode/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/os',
      'content/fastrack/rhel/server/7/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/optional/debug',
      'content/fastrack/rhel/server/7/x86_64/optional/os',
      'content/fastrack/rhel/server/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/os',
      'content/fastrack/rhel/system-z/7/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/os',
      'content/fastrack/rhel/system-z/7/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/os',
      'content/fastrack/rhel/workstation/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/os',
      'content/fastrack/rhel/workstation/7/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'webkitgtk4-2.28.2-2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkitgtk4-devel-2.28.2-2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkitgtk4-doc-2.28.2-2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkitgtk4-jsc-2.28.2-2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'webkitgtk4-jsc-devel-2.28.2-2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'webkitgtk4 / webkitgtk4-devel / webkitgtk4-doc / webkitgtk4-jsc / etc');
}
