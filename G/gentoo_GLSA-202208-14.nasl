#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-14.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(163986);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/10");

  script_cve_id(
    "CVE-2021-4129",
    "CVE-2021-4140",
    "CVE-2021-29967",
    "CVE-2021-29969",
    "CVE-2021-29970",
    "CVE-2021-29976",
    "CVE-2021-29980",
    "CVE-2021-29984",
    "CVE-2021-29985",
    "CVE-2021-29986",
    "CVE-2021-29988",
    "CVE-2021-29989",
    "CVE-2021-30547",
    "CVE-2021-38492",
    "CVE-2021-38493",
    "CVE-2021-38495",
    "CVE-2021-38503",
    "CVE-2021-38504",
    "CVE-2021-38506",
    "CVE-2021-38507",
    "CVE-2021-38508",
    "CVE-2021-38509",
    "CVE-2021-40529",
    "CVE-2021-43528",
    "CVE-2021-43529",
    "CVE-2021-43536",
    "CVE-2021-43537",
    "CVE-2021-43538",
    "CVE-2021-43539",
    "CVE-2021-43541",
    "CVE-2021-43542",
    "CVE-2021-43543",
    "CVE-2021-43545",
    "CVE-2021-43546",
    "CVE-2022-0566",
    "CVE-2022-1196",
    "CVE-2022-1197",
    "CVE-2022-1520",
    "CVE-2022-1529",
    "CVE-2022-1802",
    "CVE-2022-1834",
    "CVE-2022-2200",
    "CVE-2022-2226",
    "CVE-2022-22737",
    "CVE-2022-22738",
    "CVE-2022-22739",
    "CVE-2022-22740",
    "CVE-2022-22741",
    "CVE-2022-22742",
    "CVE-2022-22743",
    "CVE-2022-22745",
    "CVE-2022-22747",
    "CVE-2022-22748",
    "CVE-2022-22751",
    "CVE-2022-22754",
    "CVE-2022-22756",
    "CVE-2022-22759",
    "CVE-2022-22760",
    "CVE-2022-22761",
    "CVE-2022-22763",
    "CVE-2022-22764",
    "CVE-2022-24713",
    "CVE-2022-26381",
    "CVE-2022-26383",
    "CVE-2022-26384",
    "CVE-2022-26386",
    "CVE-2022-26387",
    "CVE-2022-26485",
    "CVE-2022-26486",
    "CVE-2022-28281",
    "CVE-2022-28282",
    "CVE-2022-28285",
    "CVE-2022-28286",
    "CVE-2022-28289",
    "CVE-2022-29909",
    "CVE-2022-29911",
    "CVE-2022-29912",
    "CVE-2022-29913",
    "CVE-2022-29914",
    "CVE-2022-29916",
    "CVE-2022-29917",
    "CVE-2022-31736",
    "CVE-2022-31737",
    "CVE-2022-31738",
    "CVE-2022-31740",
    "CVE-2022-31741",
    "CVE-2022-31742",
    "CVE-2022-31747",
    "CVE-2022-34468",
    "CVE-2022-34470",
    "CVE-2022-34472",
    "CVE-2022-34478",
    "CVE-2022-34479",
    "CVE-2022-34481",
    "CVE-2022-34484",
    "CVE-2022-36318",
    "CVE-2022-36319"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/21");

  script_name(english:"GLSA-202208-14 : Mozilla Thunderbird: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-14 (Mozilla Thunderbird: Multiple
Vulnerabilities)

  -  Please review the referenced CVE identifiers for details.  (CVE-2021-29967, CVE-2021-29969,
    CVE-2021-29970, CVE-2021-29976, CVE-2021-29980, CVE-2021-29984, CVE-2021-29985, CVE-2021-29986,
    CVE-2021-29988, CVE-2021-29989, CVE-2021-30547, CVE-2021-38492, CVE-2021-38493, CVE-2021-38495,
    CVE-2021-38503, CVE-2021-38504, CVE-2021-38506, CVE-2021-38507, CVE-2021-38508, CVE-2021-38509,
    CVE-2021-40529, CVE-2021-4129, CVE-2021-4140, CVE-2021-43528, CVE-2021-43529, CVE-2021-43536,
    CVE-2021-43537, CVE-2021-43538, CVE-2021-43539, CVE-2021-43541, CVE-2021-43542, CVE-2021-43543,
    CVE-2021-43545, CVE-2021-43546, CVE-2022-0566, CVE-2022-1196, CVE-2022-1197, CVE-2022-1520, CVE-2022-1529,
    CVE-2022-1802, CVE-2022-1834, CVE-2022-2200, CVE-2022-2226, CVE-2022-22737, CVE-2022-22738,
    CVE-2022-22739, CVE-2022-22740, CVE-2022-22741, CVE-2022-22742, CVE-2022-22743, CVE-2022-22745,
    CVE-2022-22747, CVE-2022-22748, CVE-2022-22751, CVE-2022-22754, CVE-2022-22756, CVE-2022-22759,
    CVE-2022-22760, CVE-2022-22761, CVE-2022-22763, CVE-2022-22764, CVE-2022-24713, CVE-2022-26381,
    CVE-2022-26383, CVE-2022-26384, CVE-2022-26386, CVE-2022-26387, CVE-2022-26485, CVE-2022-26486,
    CVE-2022-28281, CVE-2022-28282, CVE-2022-28285, CVE-2022-28286, CVE-2022-28289, CVE-2022-29909,
    CVE-2022-29911, CVE-2022-29912, CVE-2022-29913, CVE-2022-29914, CVE-2022-29916, CVE-2022-29917,
    CVE-2022-31736, CVE-2022-31737, CVE-2022-31738, CVE-2022-31740, CVE-2022-31741, CVE-2022-31742,
    CVE-2022-31747, CVE-2022-34468, CVE-2022-34470, CVE-2022-34472, CVE-2022-34478, CVE-2022-34479,
    CVE-2022-34481, CVE-2022-34484, CVE-2022-36318, CVE-2022-36319)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-14");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=794085");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=802759");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=807943");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=811912");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=813501");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=822294");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=828539");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831040");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=833520");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=834805");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=845057");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=846596");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=849047");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=857048");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=864577");
  script_set_attribute(attribute:"solution", value:
"All Mozilla Thunderbird users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-91.12.0
        
All Mozilla Thunderbird binary users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=mail-client/thunderbird-bin-91.12.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36319");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
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
    'name' : "mail-client/thunderbird",
    'unaffected' : make_list("ge 91.12.0"),
    'vulnerable' : make_list("lt 91.12.0")
  },
  {
    'name' : "mail-client/thunderbird-bin",
    'unaffected' : make_list("ge 91.12.0"),
    'vulnerable' : make_list("lt 91.12.0")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Thunderbird");
}
