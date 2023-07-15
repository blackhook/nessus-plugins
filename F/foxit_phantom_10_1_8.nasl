##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162411);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2022-25641",
    "CVE-2022-28669",
    "CVE-2022-28670",
    "CVE-2022-28671",
    "CVE-2022-28672",
    "CVE-2022-28673",
    "CVE-2022-28674",
    "CVE-2022-28675",
    "CVE-2022-28676",
    "CVE-2022-28677",
    "CVE-2022-28678",
    "CVE-2022-28679",
    "CVE-2022-28680",
    "CVE-2022-28681",
    "CVE-2022-28682",
    "CVE-2022-28683",
    "CVE-2022-30557"
  );

  script_name(english:"Foxit PhantomPDF < 10.1.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally known as Phantom) installed on the remote Windows
host is prior to 10.1.8. It is, therefore affected by multiple vulnerabilities:

  - Foxit PDF Reader and PDF Editor before 11.2.2 have a Type Confusion issue that causes a crash because of
    Unsigned32 mishandling during JavaScript execution. (CVE-2022-30557)

  - Foxit PDF Reader before 11.2.2 and PDF Editor before 11.2.2, and PhantomPDF before 10.1.8, mishandle
    cross-reference information during compressed-object parsing within signed documents. This leads to
    delivery of incorrect signature information via an Incremental Saving Attack and a Shadow Attack.
    (CVE-2022-25641)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit
    PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the target
    must visit a malicious page or open a malicious file. The specific flaw exists within the handling of Doc
    objects. The issue results from the lack of validating the existence of an object prior to performing
    operations on the object. An attacker can leverage this vulnerability to execute code in the context of
    the current process. Was ZDI-CAN-16420. (CVE-2022-28669)

  - This vulnerability allows remote attackers to disclose sensitive information on affected installations of
    Foxit PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the
    target must visit a malicious page or open a malicious file. The specific flaw exists within the
    processing of AcroForms. Crafted data in an AcroForm can trigger a read past the end of an allocated
    buffer. An attacker can leverage this in conjunction with other vulnerabilities to execute arbitrary code
    in the context of the current process. Was ZDI-CAN-16523. (CVE-2022-28670)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit
    PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the target
    must visit a malicious page or open a malicious file. The specific flaw exists within the handling of Doc
    objects. The issue results from the lack of validating the existence of an object prior to performing
    operations on the object. An attacker can leverage this vulnerability to execute code in the context of
    the current process. Was ZDI-CAN-16639. (CVE-2022-28671)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 10.1.8 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30557");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28683");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'FoxitPhantomPDF', win_local:TRUE);

var constraints = [
  { 'max_version' : '10.1.7.37777', 'fixed_version' : '10.1.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
