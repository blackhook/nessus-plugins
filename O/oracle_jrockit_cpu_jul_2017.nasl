#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101839);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-10053",
    "CVE-2017-10108",
    "CVE-2017-10109",
    "CVE-2017-10115",
    "CVE-2017-10116",
    "CVE-2017-10118",
    "CVE-2017-10135",
    "CVE-2017-10176",
    "CVE-2017-10198",
    "CVE-2017-10243"
  );
  script_bugtraq_id(
    99734,
    99774,
    99782,
    99788,
    99818,
    99827,
    99839,
    99842,
    99846,
    99847
  );

  script_name(english:"Oracle JRockit R28.3.14 Multiple Vulnerabilities (July 2017 CPU)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A programming platform installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JRockit installed on the remote Windows host is
R28.3.14. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the 2D component that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-10053)

  - Multiple unspecified flaws exist in the Serialization
    component that allow an unauthenticated, remote attacker
    to cause a denial of service condition. (CVE-2017-10108,
    CVE-2017-10109)

  - Multiple unspecified flaws exist in the JCE component
    that allow an unauthenticated, remote attacker to
    disclose sensitive information. (CVE-2017-10115,
    CVE-2017-10118, CVE-2017-10135)

  - An unspecified flaw exists in the Security component
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-10116)

  - Multiple unspecified flaws exist in the Security
    component that allow an unauthenticated, remote attacker
    to disclose sensitive information. (CVE-2017-10176,
    CVE-2017-10198)

  - An unspecified flaw exists in the JAX-WS component that
    allows an unauthenticated, remote attacker to disclose
    sensitive information or cause a denial of service
    condition. (CVE-2017-10243)

Note that vulnerability CVE-2017-10109 applies to Java deployments,
typically in clients running sandboxed Java Web Start applications or
sandboxed Java applets, that load and run untrusted code (e.g., code
that comes from the Internet) and that rely on the Java sandbox for
security. This vulnerability does not apply to Java deployments,
typically in servers, that load and run only trusted code (e.g.,
code installed by an administrator).

However, the other vulnerabilities listed above can be exploited
through sandboxed Java Web Start applications and sandboxed Java
applets. They can also be exploited by supplying data to APIs in the
specified component without using sandboxed Java Web Start
applications or sandboxed Java applets, such as through a web service.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?446d16c2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JRockit version R28.3.15 or later as referenced in
the July 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10243");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_jrockit_installed.nasl");
  script_require_keys("installed_sw/Oracle JRockit");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app     = "Oracle JRockit";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver     = install['version'];
type    = install['type'];
path    = install['path'];

if (ver =~ "^28(\.3)?$") audit(AUDIT_VER_NOT_GRANULAR, app, ver);
if (ver !~ "^28\.3($|[^0-9])") audit(AUDIT_NOT_INST, app + " 28.3.x");

# Affected :
# 28.3.14
if (ver =~ "^28\.3\.14($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  # The DLL we're looking at is a level deeper in the JDK, since it
  # keeps a subset of the JRE in a subdirectory.
  if (type == "JDK")  path += "\jre";
  path += "\bin\jrockit\jvm.dll";

  report =
    '\n  Type              : ' + type +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver  +
    '\n  Fixed version     : 28.3.15' +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

