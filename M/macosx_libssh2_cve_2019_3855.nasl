#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135851);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/23");

  script_cve_id("CVE-2019-3855");
  script_bugtraq_id(107485);

  script_name(english:"libssh2 < 1.8.1 Integer Overflow Vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The libssh2 version running on the remote host is affected by an integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"An integer overflow condition exists in libssh2 before 1.8.1  due to the way packets are read from the server. An
authenticated, local attacker can exploit this if they have already compromised an SSH server. The attacker may
be able to execute code on the system of users who connect to the SSH server.");
  script_set_attribute(attribute:"see_also", value:"https://www.libssh2.org/CVE-2019-3855.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to libssh2 version 1.8.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3855");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a::libssh2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "macosx_eval_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "Host/MacOSX/packages");
  script_require_ports("Services/ssh");

  exit(0);
}

include('vcf.inc');
include('macosx_software_eval_funcs.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

app = 'libssh2';
app_info = vcf::get_app_info(app:app);
display(app_info,'\n');

constraints = [{'min_version':'0.0', 'fixed_version':'1.8.1'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
