#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164456);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id(
    "CVE-2022-26979",
    "CVE-2022-27359",
    "CVE-2022-27944",
    "CVE-2022-34873",
    "CVE-2022-34874",
    "CVE-2022-34875",
    "CVE-2022-37376",
    "CVE-2022-37377",
    "CVE-2022-37378",
    "CVE-2022-37379",
    "CVE-2022-37380",
    "CVE-2022-37381",
    "CVE-2022-37382",
    "CVE-2022-37383",
    "CVE-2022-37384",
    "CVE-2022-37385",
    "CVE-2022-37386",
    "CVE-2022-37387",
    "CVE-2022-37388",
    "CVE-2022-37389",
    "CVE-2022-37390",
    "CVE-2022-37391"
  );

  script_name(english:"Foxit PDF Editor < 11.2.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor application (previously named Foxit PhantomPDF) installed on the remote
Windows host is prior to 11.2.3. It is, therefore affected by multiple vulnerabilities:

  - Foxit PDF Reader before 12.0.1 and PDF Editor before 12.0.1 allow a NULL pointer dereference when
    this.Span is used for oState of Collab.addStateModel, because this.Span.text can be NULL. (CVE-2022-26979)

  - Foxit PDF Reader before 12.0.1 and PDF Editor before 12.0.1 allow an exportXFAData NULL pointer
    dereference. (CVE-2022-27944)

  - This vulnerability allows remote attackers to disclose sensitive information on affected installations of
    Foxit PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the
    target must visit a malicious page or open a malicious file. The specific flaw exists within the handling
    of Annotation objects. By performing actions in JavaScript, an attacker can trigger a read past the end of
    an allocated object. An attacker can leverage this in conjunction with other vulnerabilities to execute
    arbitrary code in the context of the current process. Was ZDI-CAN-16777. (CVE-2022-34873)

  - This vulnerability allows remote attackers to disclose sensitive information on affected installations of
    Foxit PDF Reader 11.2.2.53575. User interaction is required to exploit this vulnerability in that the
    target must visit a malicious page or open a malicious file. The specific flaw exists within the handling
    of Doc objects. By performing actions in JavaScript, an attacker can trigger a read past the end of an
    allocated object. An attacker can leverage this in conjunction with other vulnerabilities to execute
    arbitrary code in the context of the current process. Was ZDI-CAN-17474. (CVE-2022-34874)

  - This vulnerability allows remote attackers to disclose sensitive information on affected installations of
    Foxit PDF Reader 11.2.1.53537. User interaction is required to exploit this vulnerability in that the
    target must visit a malicious page or open a malicious file. The specific flaw exists within the handling
    of ADBC objects. By performing actions in JavaScript, an attacker can trigger a read past the end of an
    allocated object. An attacker can leverage this in conjunction with other vulnerabilities to execute
    arbitrary code in the context of the current process. Was ZDI-CAN-16981. (CVE-2022-34875)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor version 11.2.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27359");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-37391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/26");

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
  { 'max_version' : '10.1.8.37795', 'fixed_version' : '11.2.3' },
  { 'min_version' : '11.0', 'max_version' : '11.2.2.53575', 'fixed_version' : '11.2.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
