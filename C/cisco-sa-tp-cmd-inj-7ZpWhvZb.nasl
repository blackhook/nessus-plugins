#TRUSTED 41853b79e8823757853c1ef84a7e088c261a8b4b22498f636ff755cf4dca012ce90c48b90af6930d06af8a46f26b38dfb21fd01cf86f06e0e189bd60091c5b13c73030906959be183be1214e4226e30a7d26fe7e6f4bc086793207e8679ce1e115082bc11c2b7d00f5137a0ad2eceac6b81d0e802fe59b1c5cdca0c5ce536da7664a39705022175d317e7de69bbfa093275b7bb30fa328c5dbbab22e8f8121cb72b6c9c497145ace26c14375e17b55b651d50faba65f9c1e053b0aeb31e76015e85c3e7461ffcec734e4bd8b1c74eb385b39732d4b8145dcbeda04a02312604b3df8518e008b1039dde6e0621f98d329ad8376f231de29b25893e905b373f9eb8d90e741f888909675ed72a1b96c26cc96fe346c62554d4c2bf05e87001961df551f2afab98fc623caf4f4cd2fe2fb1e2767e87b0724a6a83c1dfbe27fb5e67217503b3cd0098bba78fc6d460d8a5bfe5b0db04e8834a6d5d561bbb884b2c182484057a71f6046ca15e67c4ed37649e234d6385ff92f0c22139338689a4cb44cccc21d47ac034cd6b1c04e7f3425d79efb463d766ba34161b4a7e24298231ec95ed7852967023261e5bac10f9043f2b7f3aac55047bb6d5ee0ec7cfbb6c5f2f502fd466cdd66c4e2c1b35f8548c23a8e70d8e2e0ac98bc2161adfe882b96a792a954549d74c9978d66c64537180bc53f76b8945c56bb783c24391cce0d25228a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137856);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/13");

  script_cve_id("CVE-2020-3336");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt94558");
  script_xref(name:"CISCO-SA", value:"cisco-sa-tp-cmd-inj-7ZpWhvZb");
  script_xref(name:"IAVA", value:"2020-A-0280-S");

  script_name(english:"Cisco TelePresence Collaboration Endpoint and RoomOS Software Command Injection Vulnerability (cisco-sa-tp-cmd-inj-7ZpWhvZb)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco TelePresence CE Software is affected by a vulnerability. Please see the
included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-tp-cmd-inj-7ZpWhvZb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c846154b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt94558");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvt94558");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3336");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:telepresence_ce");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

app_name = 'Cisco TelePresence TC/CE software';
version = get_kb_item_or_exit('Cisco/TelePresence_MCU/Version');

short_version = pregmatch(pattern: "^(TC|ce)(\d+(?:\.\d+){0,2})", string:version);
if (isnull(short_version))
  audit(AUDIT_NOT_DETECT, app_name);
else
{
  short_type = short_version[1];
  short_num = short_version[2];
}

fix = '';
bugid = 'CSCvt94558';

if (short_type == 'ce'){
  if (short_num =~ "^([0-8]\.|9\.[0-8]($|[^0-9])|^9\.9)")
    fix = '9.9.4';
  else if (short_num =~ "^9\.10\.")
    fix = '9.10.2';
  else if (short_num =~ "^9\.12\.")
    fix = '9.12.3';
}
else audit(AUDIT_NOT_DETECT, app_name);

if (!empty_or_null(fix) && ver_compare(ver:short_num, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Installed Version : ' + version +
           '\n  Cisco Bug ID      : ' + bugid +
           '\n';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

