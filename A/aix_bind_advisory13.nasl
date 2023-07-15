#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102125);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2016-2775", "CVE-2016-2776");
  script_bugtraq_id(92037, 93188);
  script_xref(name:"EDB-ID", value:"40453");
  script_xref(name:"IAVA", value:"2017-A-0004");

  script_name(english:"AIX bind Advisory : bind_advisory13.asc (IV89828) (IV89829) (IV89830) (IV89831) (IV90056)");
  script_summary(english:"Checks the version of the bind packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host has a version of bind installed that is affected
by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of bind installed on the remote AIX host is affected by
the following vulnerabilities :

  - A denial of service vulnerability exists due to an error
    in the lightweight resolver (lwres) protocol
    implementation when resolving a query name that, when
    combined with a search list entry, exceeds the maximum
    allowable length. An unauthenticated, remote attacker
    can exploit this to cause a segmentation fault,
    resulting in a denial of service condition. This issue
    occurs when lwresd or the the named 'lwres' option is
    enabled. (CVE-2016-2775)

  - A denial of service vulnerability exists within file
    buffer.c due to improper construction of responses to
    crafted requests. An unauthenticated, remote attacker
    can exploit this, via a specially crafted query, to
    cause an assertion failure, resulting in a daemon exit.
    (CVE-2016-2776)");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/bind_advisory13.asc");
  script_set_attribute(attribute:"solution", value:
"A fix is available and can be downloaded from the IBM AIX website.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item("Host/AIX/version");
if (isnull(oslevel)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevel = oslevel - "AIX-";

oslevelcomplete = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (isnull(oslevelcomplete)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevelparts = split(oslevelcomplete, sep:'-', keep:0);
if ( max_index(oslevelparts) != 4 ) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
ml = oslevelparts[1];
sp = oslevelparts[2];

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This AIX package check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

aix_bind_vulns = {
  "5.3": {
    "12": {
      "09": {
        "bos.net.tcp.client": {
          "minfilesetver":"5.3.12.0",
          "maxfilesetver":"5.3.12.10",
          "patch":"(IV90056m9a|IV91253m9b|IV93366m9a|IV98825m9a)"
        },
        "bos.net.tcp.server": {
          "minfilesetver":"5.3.12.0",
          "maxfilesetver":"5.3.12.6",
          "patch":"(IV90056m9a|IV91253m9b|IV93366m9a|IV98825m9a)"
        }
      }
    }
  },
  "6.1": {
    "09": {
      "05": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV89828m5a)"
        },
        "bos.net.tcp.server": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV89828m5a)"
        }
      },
      "06": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV89828m6a|IV91254m6b|IV93361m8a)"
        },
        "bos.net.tcp.server": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV89828m6a|IV91254m6b|IV93361m8a)"
        }
      },
      "07": {
        "bos.net.tcp.client": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV89828m7a|IV91254m7b|IV93361m8a|IV98826m9a)"
        },
        "bos.net.tcp.server": {
          "minfilesetver":"6.1.9.0",
          "maxfilesetver":"6.1.9.200",
          "patch":"(IV89828m7a|IV91254m7b|IV93361m8a|IV98826m9a)"
        }
      }
    }
  },
  "7.1": {
    "03": {
      "05": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.45",
          "patch":"(IV89830m5a|IV91214m5b)"
        },
        "bos.net.tcp.server": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.45",
          "patch":"(IV89830m5a|IV91214m5b)"
        }
      },
      "06": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.46",
          "patch":"(IV89830m6d|IV91214m6a|IV93362m8a)"
        },
        "bos.net.tcp.server": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.46",
          "patch":"(IV89830m6d|IV91214m6a|IV93362m8a)"
        }
      },
      "07": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.48",
          "patch":"(IV89830m7a|IV91214m7b|IV93362m8a|IV98827m3a)"
        },
        "bos.net.tcp.server": {
          "minfilesetver":"7.1.3.0",
          "maxfilesetver":"7.1.3.48",
          "patch":"(IV89830m7a|IV91214m7b|IV93362m8a|IV98827m3a)"
        }
      }
    },
    "04": {
      "00": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV89829m1a)"
        },
        "bos.net.tcp.server": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV89829m1a)"
        }
      },
      "01": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV89829m1a|IV91255m1b|IV93363m3a)"
        },
        "bos.net.tcp.server": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV89829m1a|IV91255m1b|IV93363m3a)"
        }
      },
      "02": {
        "bos.net.tcp.client": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV89829m2a|IV91255m2a|IV93363m3a|IV98828m4a)"
        },
        "bos.net.tcp.server": {
          "minfilesetver":"7.1.4.0",
          "maxfilesetver":"7.1.4.30",
          "patch":"(IV89829m2a|IV91255m2a|IV93363m3a|IV98828m4a)"
        }
      }
    }
  },
  "7.2": {
   "00": {
      "00": {
        "bos.net.tcp.bind": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.0",
          "patch":"(IV89831m1a|IV91256m1b)"
        },
        "bos.net.tcp.bind_utils": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.1",
          "patch":"(IV89831m1a|IV91256m1b)"
        }
      },
      "01": {
        "bos.net.tcp.bind": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.0",
          "patch":"(IV89831m1a|IV91256m1b|IV93403m3a)"
        },
        "bos.net.tcp.bind_utils": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.1",
          "patch":"(IV89831m1a|IV91256m1b|IV93403m3a)"
        }
      },
      "02": {
        "bos.net.tcp.bind": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.0",
          "patch":"(IV89831m2a|IV91256m2b|IV93403m3a|IV98829m0a)"
        },
        "bos.net.tcp.bind_utils": {
          "minfilesetver":"7.2.0.0",
          "maxfilesetver":"7.2.0.1",
          "patch":"(IV89831m2a|IV91256m2b|IV93403m3a|IV98829m0a)"
        }
      }
    }
  }
};

version_report = "AIX " + oslevel;
if ( empty_or_null(aix_bind_vulns[oslevel]) ) {
  os_options = join( sort( keys(aix_bind_vulns) ), sep:' / ' );
  audit(AUDIT_OS_NOT, os_options, version_report);
}

version_report = version_report + " ML " + ml;
if ( empty_or_null(aix_bind_vulns[oslevel][ml]) ) {
  ml_options = join( sort( keys(aix_bind_vulns[oslevel]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "ML " + ml_options, version_report);
}

version_report = version_report + " SP " + sp;
if ( empty_or_null(aix_bind_vulns[oslevel][ml][sp]) ) {
  sp_options = join( sort( keys(aix_bind_vulns[oslevel][ml]) ), sep:' / ' );
  audit(AUDIT_OS_NOT, "SP " + sp_options, version_report);
}

foreach package ( keys(aix_bind_vulns[oslevel][ml][sp]) ) {
  package_info = aix_bind_vulns[oslevel][ml][sp][package];
  minfilesetver = package_info["minfilesetver"];
  maxfilesetver = package_info["maxfilesetver"];
  patch =         package_info["patch"];
  if (aix_check_ifix(release:oslevel, ml:ml, sp:sp, patch:patch, package:package, minfilesetver:minfilesetver, maxfilesetver:maxfilesetver) < 0) flag++;
}

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bos.net.tcp.client / bos.net.tcp.server / bos.net.tcp.bind / etc");
}
