# Author: Berk Can Geyikci
# Title:  Sensitive_Data_Extractor Burp Suite Custom Extension
# Tested: Burp Suite Pro 2023 2.3 with Jython 2.7.3
# Created on: 2023-03-20
# Last modified: 2023-03-20

from burp import IBurpExtender
from burp import IHttpListener
from burp import IScanIssue
from java.net import URL
import re

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Sensitive Data Extractor")
        callbacks.registerHttpListener(self)
        self._reported_issues = set()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            response = messageInfo.getResponse()
            analyzed_response = self._helpers.analyzeResponse(response)

            patterns = {
                'password': r'(?i)(password|pass|passwd)\W+\w+',
                'google_api': r'AIza[0-9A-Za-z-_]{35}',
                'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
                'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
                'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
                'amazon_aws_access_key_id' : r'AKIA[0-9A-Z]{16}',
                'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
                'amazon_aws_url2' : r"(" \
                                    r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
                                    r"|s3://[a-zA-Z0-9-\.\_]+" \
                                    r"|s3-[a-zA-Z0-9-\.\_\/]+" \
                                    r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
                                    r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
                'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
                'authorization_basic' : r'basic\s*[a-zA-Z0-9=:_\+\/-]+',
                'authorization_bearer' : r'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
                'authorization_api' : r'api[key|\s*]+[a-zA-Z0-9_\-]+',
                'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
                'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
                'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
                'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
                'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
                'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
                'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
                'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
                'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
                'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
                'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
                'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
                'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
                'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
                'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
                'slack_token' : r'\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"',
                'SSH_privKey' : r'([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)',
                'Heroku API Key' : r'[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
                'Twitter Access Token' : r'[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}',
                'MailChimp API Key': r'[0-9a-f]{32}-us[0-9]{1,2}',
                'PayPal Braintree Access Token': r'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}',
                'Picatic API Key': r'sk_live_[0-9a-z]{32}',
                'Slack Webhook': r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
                'Square Access Token': r'sq0atp-[0-9A-Za-z\\-_]{22}',
                'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\\-_]{43}',
                'Cloudinary' : r'cloudinary://.*',
                'Firebase URL' : r'.*firebaseio\.com',
                'Slack Token' : r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})',
                'Amazon AWS Access Key ID' : r'AKIA[0-9A-Z]{16}',
                'AWS API Key' : r'AKIA[0-9A-Z]{16}',
                'Google API Key' : r'AIza[0-9A-Za-z\\-_]{35}',
                'Google Cloud Platform API Key' : r'AIza[0-9A-Za-z\\-_]{35}',
                'Google Cloud Platform OAuth' : r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
                'Google Drive API Key' : r'AIza[0-9A-Za-z\\-_]{35}',
                'Google Drive OAuth' : r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
                'Google (GCP) Service-account' : r'\"type\": \"service_account\"',
                'Google Gmail API Key' : r'AIza[0-9A-Za-z\\-_]{35}',
                'Google Gmail OAuth' : r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
                'Google OAuth Access Token' : r'ya29\\.[0-9A-Za-z\\-_]+',
                'Google YouTube API Key' : r'AIza[0-9A-Za-z\\-_]{35}',
                'Google YouTube OAuth' : r'[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com',
                'Twitter OAuth' : r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
                'Password in URL': r"[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
                'Facebook OAuth' : r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
                'GitHub' : r"[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
                'Generic API Key' : r"[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
                'Generic Secret' : r"[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",

            }

            matched_data = {}
            for key, pattern in patterns.items():
                regex = re.compile(pattern)
                matches = re.findall(regex, self._helpers.bytesToString(response))
                if matches:
                    matched_data[key] = matches

            if matched_data:
                issue_url = str(messageInfo.getUrl())
                
                if issue_url in self._reported_issues:
                    return
                
                self._reported_issues.add(issue_url)

                issue_details = {}
                for key, matches in matched_data.items():
                    unique_matches = list(set(matches))
                    if unique_matches:
                        issue_details[key] = unique_matches

                issue_details_str = "<br>".join(["%s: %s<br>" % (key, ', '.join(matches)) for key, matches in issue_details.items()])
                issue = CustomScanIssue(messageInfo.getHttpService(),
                                        self._helpers.analyzeRequest(messageInfo).getUrl(),
                                        [messageInfo],
                                        "Sensitive Data Disclosure",
                                        "The response contains the following sensitive data:<br>%s" % issue_details_str,
                                        "High")
                self._callbacks.addScanIssue(issue)

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
