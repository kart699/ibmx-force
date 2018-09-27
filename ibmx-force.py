from requests.auth import HTTPBasicAuth
import yaml
import requests
import os
import logging


path = os.environ["WORKDIR"]
cert_path=path+"/certificatepath"

try:
    with open(path + "/lookup_plugins/ibmx-force/dnifconfig.yml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile)
        auth = HTTPBasicAuth(cfg['lookup_plugin']['IBMXFORCE_API_KEY'], cfg['lookup_plugin']['IBMXFORCE_API_PASS'])
except Exception, e:
    logging.error("IBM X-Force lookup plugin error in reading dnifconfig.yml: {}".format(e))


def get_dns_record(inward_array, var_array):
    # https://api.xforce.ibmcloud.com/doc/#DNS_get_resolve_input
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/resolve/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'IBM X-Force lookup Api Request Error %s' % e
            try:
                i['$IBMError'] = json_response['error']
            except Exception:
                pass
            try:
                mx_arr = []
                for mx in json_response['MX']:
                    mx_arr.append(mx['exchange'])
                i['$IBMMX'] = mx_arr
            except Exception:
                pass
            try:
                tmp_dict = {}
                for fld in json_response['Passive']['records']:
                    a = str(fld['type'])
                    if a == "ip":
                        a = "IP"
                    else:
                        a = a.title()
                    kname = str(a + "RecordType" + str(fld['recordType']).title())
                    tmp_dict.setdefault(kname, [])
                    tmp_dict[kname].append(fld['value'])
                for b in tmp_dict.keys():
                    i['$IBM' + str(b)] = tmp_dict[b]
            except Exception:
                pass
            try:
                i['$IBMTXT'] = json_response['TXT']
            except Exception:
                pass
            try:
                i['$IBMTotalRecords'] = json_response['total_rows']
            except Exception:
                pass
            try:
                i['$IBMIPv4Records'] = json_response['A']
            except Exception:
                pass
            try:
                i['$IBMIPv6Records'] = json_response['AAAA']
            except Exception:
                pass
            try:
                i['$IBMRDNS'] = json_response['RDNS']
            except Exception:
                pass
    return inward_array


def get_ip_report(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/ipr/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                a = json_response['categoryDescriptions']
                k = a.keys()
                v = a.values()
                k = ''.join(k)
                v = ''.join(v)
                if k != '':
                    i["$IBMCategory"] = k
                if v != '':
                    i['$IBMCategoryDescription'] = v
            except Exception:
                pass
            try:
                i['$IBMCountry'] = json_response['geo']['country']
            except Exception:
                pass
            try:
                i['$IBMCountryCode'] = json_response['geo']['countrycode']
            except Exception:
                pass
            try:
                hs_cat = []
                hs_ips = []
                hs_res = []
                hs_res_desc = []
                hs_geo = []
                for dt in json_response['history']:
                    if dt['categoryDescriptions'] != {}:
                        tmpd = dt['categoryDescriptions']
                        k = tmpd.keys()
                        k = ''.join(k)
                        hs_cat.append(k)
                    if dt['geo']['country'] != {}:
                        hs_geo.append(dt['geo']['country'])
                    if dt['ip'] != '' and dt['ip'] != {}:
                        hs_ips.append(dt['ip'])
                    if dt['reason'] != '' and dt['reason'] != {}:
                        hs_res.append(dt['reason'])
                    if dt['reasonDescription'] != '' and dt['reasonDescription'] != {}:
                        hs_res_desc.append(dt['reasonDescription'])
                if hs_cat:
                    i['$IBMHistoryCategoryDescription'] = list(set(hs_cat))
                i['$IBMHistoryIPSubnet'] = list(set(hs_ips))
                i['$IBMHistoryReason'] = list(set(hs_res))
                i['$IBMHistoryReasonDescription'] = list(set(hs_res_desc))
                i['$IBMHistoryCountry'] = list(set(hs_geo))
            except Exception:
                pass
            try:
                i['$IBMReason'] = json_response['reason']
            except Exception:
                pass
            try:
                i['$IBMReasonDescription'] = json_response['reasonDescription']
            except Exception:
                pass
            try:
                i['$IBMScore'] = json_response['score']
            except Exception:
                pass
            try:
                asn = []
                ascomp = []
                ascidr = []
                subnets = []
                for dt in json_response['subnets']:
                    askey = dt['asns'].keys()
                    askey = ''.join(askey)
                    asn.append(askey)
                    ascomp.append(dt['asns'][askey]['Company'])
                    ascidr.append(dt['asns'][askey]['cidr'])
                    subnets.append(dt['subnet'])
                i['$IBMSubnetASN'] = list(set(asn))
                i['$IBMSubnetASDetails'] = list(set(ascomp))
                i['$IBMSubnetASCIDR'] = list(set(ascidr))
                i['$IBMSubnets'] = list(set(subnets))
            except Exception:
                pass
    return inward_array


def get_ip_report_history(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/ipr/history/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                hs_cat = []
                hs_ips = []
                hs_res = []
                hs_res_desc = []
                hs_geo = []
                hs_geo_cn = []
                for dt in json_response['history']:
                    if dt['categoryDescriptions'] != {}:
                        tmpd = dt['categoryDescriptions']
                        k = tmpd.keys()
                        k = ''.join(k)
                        hs_cat.append(k)
                    if dt['geo']['country'] != {}:
                        hs_geo.append(dt['geo']['country'])
                    if dt['geo']['country'] != {}:
                        hs_geo_cn.append(dt['geo']['countrycode'])
                    if dt['ip'] != '' and dt['ip'] != {}:
                        hs_ips.append(dt['ip'])
                    if dt['reason'] != '' and dt['reason'] != {}:
                        hs_res.append(dt['reason'])
                    if dt['reasonDescription'] != '' and dt['reasonDescription'] != {}:
                        hs_res_desc.append(dt['reasonDescription'])
                if hs_cat:
                    i['$IBMHistoryCategoryDescription'] = list(set(hs_cat))
                if hs_ips:
                    i['$IBMHistoryIPSubnet'] = list(set(hs_ips))
                if hs_res:
                    i['$IBMHistoryReason'] = list(set(hs_res))
                if hs_res_desc:
                    i['$IBMHistoryReasonDescription'] = list(set(hs_res_desc))
                if hs_geo:
                    i['$IBMHistoryCountry'] = list(set(hs_geo))
                if hs_geo_cn:
                    i['$IBMHistoryCountryCode'] = list(set(hs_geo_cn))
            except Exception:
                pass
            try:
                asn = []
                ascomp = []
                ascidr = []
                for dt in json_response['subnets']:
                    askey = dt['asns'].keys()
                    askey = ''.join(askey)
                    asn.append(askey)
                    ascomp.append(dt['asns'][askey]['Company'])
                    ascidr.append(dt['asns'][askey]['cidr'])
                if asn:
                    i['$IBMHistoryASN'] = list(set(asn))
                if ascomp:
                    i['$IBMHistoryASDetails'] = list(set(ascomp))
                if ascidr:
                    i['$IBMHistoryCIDR'] = list(set(ascidr))
            except Exception:
                pass
            try:
                subnet_ip = []
                for sb in json_response['subnets']:
                    if sb['ip'] != '' or sb['ip'] != {}:
                        subnet_ip.append(sb['ip'])
                if subnet_ip:
                    i['$IBMSubnet'] = list(set(subnet_ip))
            except:
                pass
    return inward_array


def get_ip_malware(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/ipr/malware/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                tmp_dict = {}
                for fld in json_response['malware']:
                    dname = str(fld['type']) + str("Domain")
                    fname = str(fld['type']) + str("Family")
                    md5name = str(fld['type']) + str("MD5")
                    uriname = str(fld['type']) + str("URI")
                    tmp_dict.setdefault(dname, [])
                    tmp_dict.setdefault(fname, [])
                    tmp_dict.setdefault(md5name, [])
                    tmp_dict.setdefault(uriname, [])
                    tmp_dict[dname].append(fld['domain'])
                    tmp_dict[fname].append(''.join(fld['family']))
                    tmp_dict[md5name].append(fld['md5'])
                    tmp_dict[uriname].append(fld['uri'])
                for b in tmp_dict.keys():
                    i['$IBM' + str(b)] = list(set(tmp_dict[b]))
            except Exception:
                pass
    return inward_array


def get_asn_network(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/ipr/asn/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                i['$IBMNetworks'] = json_response['networks']
            except Exception:
                pass
    return inward_array


def get_hash_malware(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/malware/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:

                i['$IBMmd5'] = json_response['malware']['md5']
            except Exception:
                pass
            try:
                i['$IBMRisk'] = json_response['malware']['risk']
            except Exception:
                pass
            try:
                i['$IBMDetectionCoverage'] = json_response['malware']['origins']['external']['detectionCoverage']
            except Exception:
                pass
            try:
                if json_response['malware']['origins']['external']['family'] != None:
                    i['$IBMMalwareFamily'] = json_response['malware']['origins']['external']['family']
            except Exception:
                pass
    return inward_array


def get_malware_family(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/malware/family/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                i['$IBMMalwareFamily'] = json_response['family']
            except Exception:
                pass
            try:
                i['$IBMMalwareFirstSeen'] = json_response['firstseen']
            except Exception:
                pass
            try:
                i['$IBMMalwareLastSeen'] = json_response['lastseen']
            except Exception:
                pass
            try:
                i['$IBMMalwareCount'] = json_response['count']
            except Exception:
                pass
            try:
                family = []
                md5hash = []
                for mdata in json_response['malware']:
                    if mdata['family'] != []:
                        family.append(mdata['family'])
                    if mdata['md5'] != '':
                        md5hash.append(mdata['md5'])
                if len(md5hash) > 0:
                    i['$IBMMalwareMd5'] = list(set(md5hash))
            except Exception:
                pass
    return inward_array


def get_malware_family_wildcard(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/malware/familyext/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                i['$IBMMalwareFamily'] = json_response['family']
            except Exception:
                pass
            try:
                i['$IBMMalwareFirstSeen'] = json_response['firstseen']
            except Exception:
                pass
            try:
                i['$IBMMalwareLastSeen'] = json_response['lastseen']
            except Exception:
                pass
            try:
                md5hashes = []
                for mdata in json_response['malware']:
                    md5hashes.append(mdata['md5'])
                if len(md5hashes) > 0:
                    i['$IBMMalwareMd5'] = md5hashes
            except Exception:
                pass
    return inward_array


def get_url_report(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/url/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                a = json_response['result']['categoryDescriptions']
                k = a.keys()
                v = a.values()
                i['$IBMCategory'] = k
                i['$IBMCategoryDescription'] = v
            except Exception:
                pass
            try:
                i['$IBMScore'] = json_response['result']['score']
            except Exception:
                pass
    return inward_array


def get_url_malware(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/url/malware/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                i['$IBMCount'] = json_response['count']
            except Exception:
                pass
            try:
                domain = []
                family = []
                ip = []
                md5 = []
                uri = []
                type = []
                filepath = []
                for mldata in json_response['malware']:
                    domain.append(mldata['domain'])
                    fm = mldata['family']
                    fm = ''.join(fm)
                    family.append(fm)
                    filepath.append(mldata['filepath'])
                    ip.append(mldata['ip'])
                    md5.append(mldata['md5'])
                    uri.append(mldata['uri'])
                    type.append(mldata['type'])
                i['$IBMMalwareDomain'] = list(set(domain))
                i['$IBMMalwareFamily'] = list(set(family))
                i['$IBMMalwareFilePath'] = list(set(filepath))
                i['$IBMMalwareIP'] = list(set(ip))
                i['$IBMMalwareMd5'] = list(set(md5))
                i['$IBMMalwareURI'] = list(set(uri))
                i['$IBMMalwareType'] = list(set(type))
            except Exception:
                pass

    return inward_array


def get_whois(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/whois/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                for data in json_response['contact']:
                    tmp_lst = []
                    tmp_lst = data.keys()
                    c = []
                    for di in tmp_lst:
                        c.append(str(''.join(di)))
                    c = [x for x in c if x != 'type']
                    for j in c:
                        a = str(data['type']).title()
                        b = str(j).title()
                        i['$IBM' + a + b] = data[j]
            except Exception, e:
                pass
            try:
                i['$IBMContactEmail'] = json_response['contactEmail']
            except KeyError:
                pass
            try:
                i['$IBMRegistrarName'] = json_response['registrarName']
            except KeyError:
                pass
            try:
                i['$IBMCreatedDate'] = str(json_response['createdDate'])[:-5]
            except KeyError:
                pass
            try:
                i['$IBMExpiresDate'] = json_response['expiresDate'][:-5]
            except KeyError:
                pass
            try:
                i['$IBMUpdatedDate'] = json_response['updatedDate'][:-5]
            except KeyError:
                pass
    return inward_array


def get_by_xfid(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/vulnerabilities/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                i['$IBMVulnerabilityConsequences'] = json_response['consequences']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityAccessComplexity'] = json_response['cvss']['access_complexity']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityAccessVector'] = json_response['cvss']['access_vector']
            except Exception:
                pass
            try:
                if json_response['cvss']['authentication'] == None:
                    i['$IBMVulnerabilityAuthentication'] = 'None'
                else:
                    i['$IBMVulnerabilityAuthentication'] = json_response['cvss']['authentication']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityAvailabilityImpact'] = json_response['cvss']['availability_impact']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityConfidentialityImpact'] = json_response['cvss']['confidentiality_impact']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityIntegrityImpact'] = json_response['cvss']['integrity_impact']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityRemediationLevel'] = json_response['cvss']['remediation_level']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityVersion'] = json_response['cvss']['version']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityDescription'] = json_response['description']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityExploitability'] = json_response['exploitability']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityAffectedPlatforms'] = json_response['platforms_affected']
            except Exception:
                pass
            try:
                desc = []
                linktarget = []
                for data in json_response['references']:
                    desc.append(data['description'])
                    linktarget.append(data['link_target'])
                i['$IBMReferencesDescription'] = list(set(desc))
                i['$IBMReferencesTargetLink'] = list(set(linktarget))
            except Exception:
                pass
            try:
                i['$IBMRemedy'] = json_response['remedy']
            except Exception:
                pass
            try:
                i['$IBMRemedyFormat'] = json_response['remedy_fmt']
            except Exception:
                pass
            try:
                i['$IBMReportConfidence'] = json_response['report_confidence']
            except Exception:
                pass
            try:
                i['$IBMReported'] = json_response['reported']
            except Exception:
                pass
            try:
                i['$IBMRiskLevel'] = json_response['risk_level']
            except Exception:
                pass
            try:
                i['$IBMSTDcode'] = json_response['stdcode']
            except Exception:
                pass
            try:
                if json_response['tagname'] != '':
                    i['$IBMTagname'] = json_response['tagname']
            except Exception:
                pass
            try:
                if json_response['tags'] != []:
                    i['$IBMTags'] = json_response['tags']
            except Exception:
                pass
            try:
                if json_response['temporal_score'] != '':
                    i['$IBMTemporalScore'] = json_response['temporal_score']
            except Exception:
                pass
            try:
                if json_response['title'] != '':
                    i['$IBMTitle'] = json_response['title']
            except Exception:
                pass
            try:
                if json_response['type'] != '':
                    i['$IBMType'] = json_response['type']
            except Exception:
                pass
            try:
                if json_response['updateid'] != '':
                    i['$IBMUpdateID'] = json_response['updateid']
            except Exception:
                pass
            try:
                if json_response['uuid'] != '':
                    i['$IBMUUID'] = json_response['uuid']
            except Exception:
                pass
            try:
                if json_response['variant'] != '':
                    i['$IBMVariant'] = json_response['variant']
            except Exception:
                pass
            try:
                if json_response['xfdbid'] != '':
                    i['$IBMxfdbid'] = json_response['xfdbid']
            except Exception:
                pass
    return inward_array


def get_by_stdcode(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/vulnerabilities/search/' + params, auth=auth,verify=cert_path)
                j_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                json_response = {}
                for dt in j_response:
                    json_response.update(dt)
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityConsequences'] = json_response['consequences']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityAccessComplexity'] = json_response['cvss']['access_complexity']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityAccessVector'] = json_response['cvss']['access_vector']
            except Exception:
                pass
            try:
                if json_response['cvss']['authentication'] == None:
                    i['$IBMVulnerabilityAuthentication'] = 'None'
                else:
                    i['$IBMVulnerabilityAuthentication'] = json_response['cvss']['authentication']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityAvailabilityImpact'] = json_response['cvss']['availability_impact']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityConfidentialityImpact'] = json_response['cvss']['confidentiality_impact']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityIntegrityImpact'] = json_response['cvss']['integrity_impact']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityRemediationLevel'] = json_response['cvss']['remediation_level']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityVersion'] = json_response['cvss']['version']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityDescription'] = json_response['description']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityExploitability'] = json_response['exploitability']
            except Exception:
                pass
            try:
                i['$IBMVulnerabilityAffectedPlatforms'] = json_response['platforms_affected']
            except Exception:
                pass
            try:
                desc = []
                linktarget = []
                for data in json_response['references']:
                    desc.append(data['description'])
                    linktarget.append(data['link_target'])
                i['$IBMReferencesDescription'] = list(set(desc))
                i['$IBMReferencesTargetLink'] = list(set(linktarget))
            except Exception:
                pass
            try:
                i['$IBMRemedy'] = json_response['remedy']
            except Exception:
                pass
            try:
                i['$IBMRemedyFormat'] = json_response['remedy_fmt']
            except Exception:
                pass
            try:
                i['$IBMReportConfidence'] = json_response['report_confidence']
            except Exception:
                pass
            try:
                i['$IBMReported'] = json_response['reported']
            except Exception:
                pass
            try:
                i['$IBMRiskLevel'] = json_response['risk_level']
            except Exception:
                pass
            try:
                i['$IBMSTDcode'] = json_response['stdcode']
            except Exception:
                pass
            try:
                if json_response['tagname'] != '':
                    i['$IBMTagname'] = json_response['tagname']
            except Exception:
                pass
            try:
                if json_response['tags'] != []:
                    i['$IBMTags'] = json_response['tags']
            except Exception:
                pass
            try:
                if json_response['temporal_score'] != '':
                    i['$IBMTemporalScore'] = json_response['temporal_score']
            except Exception:
                pass
            try:
                if json_response['title'] != '':
                    i['$IBMTitle'] = json_response['title']
            except Exception:
                pass
            try:
                if json_response['type'] != '':
                    i['$IBMType'] = json_response['type']
            except Exception:
                pass
            try:
                if json_response['updateid'] != '':
                    i['$IBMUpdateID'] = json_response['updateid']
            except Exception:
                pass
            try:
                if json_response['uuid'] != '':
                    i['$IBMUUID'] = json_response['uuid']
            except Exception:
                pass
            try:
                if json_response['variant'] != '':
                    i['$IBMVariant'] = json_response['variant']
            except Exception:
                pass
            try:
                if json_response['xfdbid'] != '':
                    i['$IBMxfdbid'] = json_response['xfdbid']
            except Exception:
                pass
    return inward_array


def get_by_msid(inward_array, var_array):
    # http://api.passivetotal.org/api/docs/
    for i in inward_array:
        if var_array[0] in i:
            params = str(i[var_array[0]])
            try:
                response = requests.get('https://api.xforce.ibmcloud.com/vulnerabilities/msid/' + params, auth=auth,verify=cert_path)
                json_response = response.json()
            except Exception, e:
                print 'Api Request Error %s' % e
            try:
                std = []
                ref = []
                report_dt = []
                ttle = []
                xfdbid = []
                for dt in json_response:
                    if 'reference' in dt.keys():
                        ref.append(dt['reference'])
                    if 'reported' in dt.keys():
                        report_dt.append(dt['reported'])
                    if 'title' in dt.keys():
                        ttle.append(dt['title'])
                    if 'xfdbid' in dt.keys():
                        xfdbid.append(dt['xfdbid'])
                    if 'stdcode' in dt.keys():
                        a = (dt['stdcode'])
                        a = ''.join(a)
                        std.append(a)
                i['$IBMReference'] = list(set(ref))
                i['$IBMReported'] = list(set(report_dt))
                i['$IBMTitle'] = list(set(ttle))
                i['$IBMXFDBID'] = list(set(xfdbid))
                i['$IBMSTDcode'] = list(set(std))
            except Exception:
                pass
    return inward_array


