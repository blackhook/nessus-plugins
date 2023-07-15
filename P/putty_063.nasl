#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69318);
  script_version("1.9");
  script_cvs_date("Date: 2018/11/26 11:02:16");

  script_cve_id(
    "CVE-2013-4206",
    "CVE-2013-4207",
    "CVE-2013-4208",
    "CVE-2013-4852"
  );
  script_bugtraq_id(61599, 61644, 61645, 61649);

  script_name(english:"PuTTY 0.52 to 0.62 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PuTTY.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an SSH client that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has an installation of PuTTY version 0.52 or greater
but earlier than version 0.63.  As such, it is reportedly affected by
the following vulnerabilities :

  - An overflow error exists in the function 'modmul' in
    the file 'putty/sshbn.c' that could allow heap
    corruption when handling DSA signatures. (CVE-2013-4206)

  - A buffer overflow error exists related to modular
    inverse calculation, non-coprime values and DSA
    signature verification. (CVE-2013-4207)

  - An error exists in the file 'putty/sshdss.c' that could
    allow disclosure of private key material.
    (CVE-2013-4208)

  - Multiple overflow errors exist in the files 'sshrsa.c'
    and 'sshdss.c'. (CVE-2013-4852)");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-signature-stringlen.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4834e145");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-modmul.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20c27652");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/private-key-not-wiped.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bdd07a8");
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-bignum-division-by-zero.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1b0243c");
  script_set_attribute(attribute:"see_also", value:"https://www.search-lab.hu/advisories/secadv-20130722");

  script_set_attribute(attribute:"solution", value:"Upgrade to PuTTY version 0.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4206");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("putty_installed.nasl");
  script_require_keys("installed_sw/PuTTY", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"PuTTY", win_local:TRUE);

constraints = [
  { "min_version" : "0.52", "fixed_version" : "0.63" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
