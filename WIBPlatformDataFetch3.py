
#!/usr/bin/python3.10

# --------------------------------------------------------------------------------------------------------------
# ToDo:
#
#   1) Add 'Severities' (parameter/list) to 'Vulnerabilities' and 'Misconfigurations' data pull...
#
# --------------------------------------------------------------------------------------------------------------

import optparse
import os
import traceback
import platform
import re
import string
import sys
import collections
import shutil
import time
import math
import base64
import html
import json
import asyncio
import aiohttp

from datetime    import datetime
from datetime    import timedelta
from collections import OrderedDict 
from bson        import json_util

dictPy3GblEnv = collections.defaultdict()

# - - - - - Setup the Python3 'Global' Environment dictionary (standard) - - - - -

dictPy3GblEnv["bVerbose"]                     = False
dictPy3GblEnv["bProcessingError"]             = False
dictPy3GblEnv["optParser"]                    = optparse.OptionParser()
dictPy3GblEnv["sScriptId"]                    = dictPy3GblEnv["optParser"].get_prog_name()
dictPy3GblEnv["sScriptVers"]                  = "(v1.0401)"
dictPy3GblEnv["sScriptDisp"]                  = ("%s %s:" % (dictPy3GblEnv["sScriptId"], dictPy3GblEnv["sScriptVers"]))
dictPy3GblEnv["cScriptArgc"]                  = len(sys.argv)
dictPy3GblEnv["sScriptOutputWIBPlatformFile"] = None

# - - - - - Setup the Python3 'Global' Environment dictionary (extended) - - - - -

dictPy3GblEnv["tmStartTime"]                  = time.time()
dictPy3GblEnv["dtStartTime"]                  = datetime.now()
dictPy3GblEnv["cHttpGetRequests"]             = 0
dictPy3GblEnv["cHttpPostRequests"]            = 0
dictPy3GblEnv["sCurrentWorkingDir"]           = os.getcwd()
dictPy3GblEnv["sPythonVers"]                  = ("v%s.%s.%s" % (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)) 
dictPy3GblEnv["sServerNode"]                  = platform.node()
dictPy3GblEnv["sPlatform"]                    = platform.system()
dictPy3GblEnv["sPlatformPathSep"]             = None
dictPy3GblEnv["bPlatformIsWindows"]           = dictPy3GblEnv["sPlatform"].startswith('Windows')

if dictPy3GblEnv["bPlatformIsWindows"] == False:

    dictPy3GblEnv["bPlatformIsWindows"] = dictPy3GblEnv["sPlatform"].startswith('Microsoft')

if dictPy3GblEnv["bPlatformIsWindows"] == True:

    dictPy3GblEnv["sPlatformPathSep"] = "\\"

else:

    dictPy3GblEnv["sPlatformPathSep"] = "/"

# Parameter and Application 'global' item(s):

# ctPy3GblEnv["sWIBPlatformServerHost"]           = "wib-product.wib-security.com"
dictPy3GblEnv["sWIBPlatformServerHost"]           = "demo.wib-security.com"
dictPy3GblEnv["sWIBPlatformServerPort"]           = "443"
dictPy3GblEnv["sWIBPlatformUsername"]             = None
dictPy3GblEnv["sWIBPlatformPassword"]             = None

dictPy3GblEnv["sWIBStatisticsDays"]               = None
dictPy3GblEnv["sWIBStatisticsStartDate"]          = (dictPy3GblEnv["dtStartTime"] - timedelta(days=7)).strftime("%Y-%m-%d")
dictPy3GblEnv["sWIBStatisticsEndDate"]            = dictPy3GblEnv["dtStartTime"].strftime("%Y-%m-%d")

dictPy3GblEnv["sWIBIncidentsSeverity"]            = None
dictPy3GblEnv["listWIBIncidentsSeverity"]         = None
dictPy3GblEnv["sWIBVulnerabilitiesSeverity"]      = None
dictPy3GblEnv["listWIBVulnerabilitiesSeverity"]   = None
dictPy3GblEnv["sWIBMisconfigurationsSeverity"]    = None
dictPy3GblEnv["listWIBMisconfigurationsSeverity"] = None

dictPy3GblEnv["sWIBIncidentsStartTime"]           = (dictPy3GblEnv["dtStartTime"] - timedelta(days=30)).isoformat(sep='T', timespec='milliseconds')+"Z"
dictPy3GblEnv["sWIBIncidentsEndTime"]             = dictPy3GblEnv["dtStartTime"].isoformat(sep='T', timespec='milliseconds')+"Z"
dictPy3GblEnv["sWIBIncidentsDays"]                = None
dictPy3GblEnv["sWIBIncidentsLimit"]               = None
dictPy3GblEnv["cWIBIncidentsAPIMax"]              = 200

dictPy3GblEnv["sWIBVulnerabilitiesStartTime"]     = (dictPy3GblEnv["dtStartTime"] - timedelta(days=30)).isoformat(sep='T', timespec='milliseconds')+"Z"
dictPy3GblEnv["sWIBVulnerabilitiesEndTime"]       = dictPy3GblEnv["dtStartTime"].isoformat(sep='T', timespec='milliseconds')+"Z"
dictPy3GblEnv["sWIBVulnerabilitiesDays"]          = None
dictPy3GblEnv["sWIBVulnerabilitiesLimit"]         = None
dictPy3GblEnv["cWIBVulnerabilitiesAPIMax"]        = 50

dictPy3GblEnv["sWIBMisconfigurationsStartTime"]   = (dictPy3GblEnv["dtStartTime"] - timedelta(days=30)).isoformat(sep='T', timespec='milliseconds')+"Z"
dictPy3GblEnv["sWIBMisconfigurationsEndTime"]     = dictPy3GblEnv["dtStartTime"].isoformat(sep='T', timespec='milliseconds')+"Z"
dictPy3GblEnv["sWIBMisconfigurationsDays"]        = None
dictPy3GblEnv["sWIBMisconfigurationsLimit"]       = None
dictPy3GblEnv["cWIBMisconfigurationsAPIMax"]      = 20

dictPy3GblEnv["sWIBEndpointsLimit"]               = None
dictPy3GblEnv["cWIBEndpointsAPIMax"]              = 50

dictPy3GblEnv["sWIBHostnamesLimit"]               = None
dictPy3GblEnv["cWIBHostnamesAPIMax"]              = 50

dictPy3GblEnv["sWIBRepositoriesLimit"]            = None
dictPy3GblEnv["cWIBRepositoriesAPIMax"]           = 50

dictPy3GblEnv["sWIBAccessTokenType"]              = "Bearer"
dictPy3GblEnv["sWIBAccessToken"]                  = ""
# Example:                                        = "eyJhbGciOiJSUzI1NiIsImtpZCI6IkFFRUYyQUE2RTgxNTVGMjY2MDMzNjM1MzcyQjgxODNEMzUxODUyQUEiLCJ0eXAiOiJKV1QiLCJ4NXQiOiJydThxcHVnVlh5WmdNMk5UY3JnWVBUVVlVcW8ifQ.eyJuYmYiOjE2NDAwMTY4NTksImV4cCI6MTY0MDAyMDQ1OSwiaXNzIjoiaHR0cDovL0RBUllMQ09YRTM2Qy9DeFJlc3RBUEkvYXV0aC9pZGVudGl0eSIsImF1ZCI6WyJodHRwOi8vREFSWUxDT1hFMzZDL0N4UmVzdEFQSS9hdXRoL2lkZW50aXR5L3Jlc291cmNlcyIsInJlcG9ydGluZ19hcGkiXSwiY2xpZW50X2lkIjoicmVwb3J0aW5nX3NlcnZpY2Vfc3dhZ2dlciIsInN1YiI6IjEiLCJhdXRoX3RpbWUiOjE2NDAwMTY2ODcsImlkcCI6ImxvY2FsIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiZGNveCIsInRlYW0iOlsiL0N4U2VydmVyIiwiL0N4U2VydmVyL1NQIiwiL0N4U2VydmVyL1NQL0NvbXBhbnkiLCIvQ3hTZXJ2ZXIvU1AvQ29tcGFueS9Vc2VycyIsIi9DeFNlcnZlci9TUC9Db21wYW55L1VzZXJzL0RhcnlsX0NveCJdLCJzYXN0LXBlcm1pc3Npb25zIjpbInNhdmUtb3NhLXNjYW4iLCJzYXZlLXNhc3Qtc2NhbiIsInNhdmUtcHJvamVjdCIsInZpZXctZmFpbGVkLXNhc3Qtc2NhbiIsIm9wZW4taXNzdWUtdHJhY2tpbmctdGlja2V0cyIsImNyZWF0ZS1wcmVzZXQiLCJkb3dubG9hZC1zY2FuLWxvZyIsInNlZS1zdXBwb3J0LWxpbmsiLCJ2aWV3LXJlc3VsdHMiLCJtYW5hZ2UtZGF0YS1hbmFseXNpcy10ZW1wbGF0ZXMiLCJnZW5lcmF0ZS1zY2FuLXJlcG9ydCIsIm1hbmFnZS1yZXN1bHQtY29tbWVudCIsImV4cG9ydC1zY2FuLXJlc3VsdHMiLCJ1c2UtY3hhdWRpdCIsIm1hbmFnZS1jdXN0b20tZGVzY3JpcHRpb24iLCJ1cGRhdGUtYW5kLWRlbGV0ZS1wcmVzZXQiLCJtYW5hZ2UtcmVzdWx0LXNldmVyaXR5IiwibWFuYWdlLXJlc3VsdC1hc3NpZ25lZSIsInNldC1yZXN1bHQtc3RhdGUtdG92ZXJpZnkiLCJzZXQtcmVzdWx0LXN0YXRlLWNvbmZpcm1lZCIsInNldC1yZXN1bHQtc3RhdGUtdXJnZW50Iiwic2V0LXJlc3VsdC1zdGF0ZS1wcm9wb3NlZG5vdGV4cGxvaXRhYmxlIiwic2V0LXJlc3VsdC1zdGF0ZS1iYWNrbG9nIiwic2V0LXJlc3VsdC1zdGF0ZS1pZ25vcmUiLCJzZXQtcmVzdWx0LXN0YXRlLWZhbHNlcG9zaXRpdmUiLCJzZXQtcmVzdWx0LXN0YXRlLW5vdGV4cGxvaXRhYmxlIiwiZGVsZXRlLXNhc3Qtc2NhbiIsImRlbGV0ZS1wcm9qZWN0IiwidXNlLW9kYXRhIiwibWFuYWdlLWRhdGEtcmV0ZW50aW9uIiwibWFuYWdlLWVuZ2luZS1zZXJ2ZXJzIiwibWFuYWdlLXN5c3RlbS1zZXR0aW5ncyIsIm1hbmFnZS1leHRlcm5hbC1zZXJ2aWNlcy1zZXR0aW5ncyIsIm1hbmFnZS1jdXN0b20tZmllbGRzIiwibWFuYWdlLWlzc3VlLXRyYWNraW5nLXN5c3RlbXMiLCJtYW5hZ2UtcHJlLXBvc3Qtc2Nhbi1hY3Rpb25zIiwiZG93bmxvYWQtc3lzdGVtLWxvZ3MiXSwic2NvcGUiOlsicmVwb3J0aW5nX2FwaSJdLCJhbXIiOlsicHdkIl19.Gq6XX37rF1BVjOXLYBfEcuYmR56vM08Chmd0aag0XpKq-YZ-MgG2O_3KyDs9BQBPmohDX6qyMH2_N7LyfGY5MsGK9bWFDL6JiXuQ5YtUa7_fBZrxx7jbSbmYjomJiKG7SHXlyeGsPLJ1DyDjqJJ3zCNq_i-ekGEhUKwN2DJuB5gNmVlVKnZakUKwn4OkgS2ivsH3qNZnbCY37QGKaL2MuJ2S16-EVpORlyUWFn-XvIaUWFR5gTNfiFVBugaF9PFuq6yPKMXYxhkyrZcfJ8RTeiE5xbcy_1BW0Vyc8U3MxiTom4WIndXav6O1_yPogHBKWXybwR0L4F6ilqe6Ycps4A" 
# NOTE: The token above is 'stolen' from the Web browser 'auth' and implicit response...

# Class to handle all 'http'/'https' 'client' traffic and requests:

class HttpRequestHandlerClient(object):

    sClassMod         = __name__
    sClassId          = "HttpRequestHandlerClient"
    sClassVers        = "(v0.0000)"
    sClassDisp        = sClassMod+"."+sClassId+" "+sClassVers+": "

    dictPy3GblEnv     = None
    dictReqHandlerEnv = None

    def __init__(self, dictPy3GblEnv=None):

        try:

            self.setPy3GblEnv(dictPy3GblEnv=dictPy3GblEnv)

            if self.sClassMod == "__main__":

                self.sClassMod = "<<<Class>>>"

            self.sClassVers = self.dictPy3GblEnv["sScriptVers"]
            self.sClassDisp = self.sClassMod+"."+self.sClassId+" "+self.sClassVers+": "

            self.dictReqHandlerEnv = collections.defaultdict()

            # - - - - - Setup the AioHttp 'Request' Handler Environment dictionary (standard) - - - - -

            self.dictReqHandlerEnv["sReqHandlerId"]              = self.sClassId
            self.dictReqHandlerEnv["sReqHandlerVers"]            = self.sClassVers
            self.dictReqHandlerEnv["sReqHandlerDisp"]            = self.sClassDisp

            self.dictReqHandlerEnv["wibAioHttpSession"]          = None
            self.dictReqHandlerEnv["sWIBReqIncidentsOutputFile"] = None

        except Exception as inst:

            print("%s '__init__()' - exception occured..." % (self.sClassDisp))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ")

    def getPy3GblEnv(self):

        return self.dictPy3GblEnv

    def setPy3GblEnv(self, dictPy3GblEnv=False):

        self.dictPy3GblEnv = dictPy3GblEnv

    def dump_fields(self):

        if self.dictPy3GblEnv["bVerbose"] == True:

            print("%s Dump of the variable(s) content of this class:" % (self.sClassDisp))
            print("%s The contents of 'dictPy3GblEnv' is [%s]..." % (self.sClassDisp, self.dictPy3GblEnv))
            print("%s The contents of 'dictReqHandlerEnv' is [%s]..." % (self.sClassDisp, self.dictReqHandlerEnv))

    def toString(self):

        asObjDetail = list();

        asObjDetail.append("'sClassDisp' is [%s], " % (self.sClassDisp))
        asObjDetail.append("'dictPy3GblEnv' is [%s], " % (self.dictPy3GblEnv))
        asObjDetail.append("'dictReqHandlerEnv' is [%s]. " % (self.dictReqHandlerEnv))

        return ''.join(asObjDetail)

    def __str__(self):

        return self.toString()

    def __repr__(self):

        return self.toString()

    async def retrieveWIBPortalData(self) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        async with aiohttp.ClientSession() as self.dictReqHandlerEnv["wibAioHttpSession"]:

            if self.dictPy3GblEnv["sWIBAccessToken"] != None:
 
                self.dictPy3GblEnv["sWIBAccessToken"] = self.dictPy3GblEnv["sWIBAccessToken"].strip()
 
            if self.dictPy3GblEnv["sWIBAccessToken"] == None or \
               len(self.dictPy3GblEnv["sWIBAccessToken"]) < 1:
 
                await self.__connectHttpClientSession()

            else:

                await self.__connectHttpClientSessionExistingToken()

            if self.dictPy3GblEnv["bProcessingError"] == True:
            
                print("%s 'HttpRequestHandlerClient.__connectHttpClientSessionXXX()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))

                return

            await self.__gatherAllWIBPortalData()

            if self.dictPy3GblEnv["bProcessingError"] == True:
            
                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))

                return

            await self.__outputWIBPlatformData()

            if self.dictPy3GblEnv["bProcessingError"] == True:

                print("%s 'HttpRequestHandlerClient.__outputWIBPlatformData()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))

                return

        return

    async def __connectHttpClientSessionExistingToken(self) -> None:
 
        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"
 
        try:
 
        # =====================================================================================================
        #   # This version does NOT make a call to get the 'identity' token (it's 'stolen' from the browser)...
        #
        #   await self.retrieveOAuth2IdentityConnectToken()
        #
        #   if self.dictPy3GblEnv["bProcessingError"] == True:
        #
        #       return
        # =====================================================================================================
 
            if self.dictPy3GblEnv["sWIBAccessToken"] != None:
 
                self.dictPy3GblEnv["sWIBAccessToken"] = self.dictPy3GblEnv["sWIBAccessToken"].strip()
 
            if self.dictPy3GblEnv["sWIBAccessToken"] == None or \
               len(self.dictPy3GblEnv["sWIBAccessToken"]) < 1:
 
                self.dictPy3GblEnv["bProcessingError"] = True
 
                print("%s 'HttpRequestHandlerClient.__connectHttpClientSessionExistingToken()' - 'client' Session failed to obtain an OAuth2 'access' Token and 'authorize' grant - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)
 
                return

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictPy3GblEnv["sWIBAccessToken"]
 
            return
 
        except Exception as inst:
 
            print("%s 'HttpRequestHandlerClient.__connectHttpClientSessionExistingToken()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)
 
            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)
 
            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)
 
            self.dictPy3GblEnv["bProcessingError"] = True
 
    async def __connectHttpClientSession(self) -> None:

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
        #
        # <FIX THIS> Doc was for Checkmarx...
        #
        # This API generates a JWT (JSON Web Token) access token which is used
        # for authentication with all Checkmarx One APIs.
        #
        # The access token is valid for a 30 minute session.
        #
        # There are two methods that can be used to generate an access token:
        #
        #     Refresh Token (API Key) -
        #       If you have a refresh token, you can submit that with this API
        #       in order to receive an access token. To learn how to generate a 
        #       refresh token, see Generating a Refresh Token (API Key).
        #
        #     OAuth2 Client -
        #       If you have an OAuth2 Client for Checkmarx One, you can submit
        #       your Client ID and Secret with this API in order to receive an
        #       access token. To learn how to generate an OAuth2 Client, see
        #       Creating an Oauth2 Client.
        #
        #       The access token inherits whichever roles (permissions) are
        #       assigned to the OAuth2 Client.
        #
        #     In addition to returning an access token, this API also returns a
        #     new refresh token which can be used for future login requests.
        #
        # Method -> POST
        #
        # Workflow
        #
        #     1) Use the Authentication API to generate an access token
        #     2) Use the access token for authentication of all APIs
        #
        # URL
        #
        #     US Environment - https://
        #
        # Curl Sample <Refresh Token>
        #
        #     curl \
        #       -X POST \
        #       https://iam.checkmarx.net/auth/realms/{{TENANT_NAME}}/protocol/openid-connect/token \
        #       --data "grant_type=refresh_token" \
        #       --data "client_id=ast-app" \
        #       --data "refresh_token={{Your_API_KEY}}"
        #
        # Curl Sample <OAuth2 Client>
        #
        #     curl \
        #       --location 
        #       --request POST 'https://eu.iam.checkmarx.net/auth/realms/{{TENANT_NAME}}/protocol/openid-connect/token ' \
        #       --header 'Content-Type: application/x-www-form-urlencoded' \
        #       --header 'Accept: application/json' \
        #       --data-urlencode 'client_id={{your-iam-oauth-client}}' \
        #       --data-urlencode 'grant_type=client_credentials' \
        #       --data-urlencode 'client_secret={{secret_key}}'
        #
        # Media Type (header) -> Accept: application/json
        #
        # Parameters
        #
        #     All Parameters are required (depending on the specified grant_type)
        #
        #    See the following link for all parameter/response/error-response data: 
        #
        #       https://checkmarx.com/resource/documents/en/34965-68774-authentication-api.html
        #
        # Sample Success Response <Code: 200 Authenticated>
        #
        # {
        #     "access_token": "eyJhbGciOiJSUzI1NiIsInR...phQlk0nAGjOtvG8UT-8iaA",
        #     "token_type": "bearer"
        # }
        #
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        try:

            self.dictPy3GblEnv["bProcessingError"]                   = False

            self.dictReqHandlerEnv["dictWIBResponseAccess"]          = None

            self.dictReqHandlerEnv["dictWIBAccessToken"]             = None
            self.dictReqHandlerEnv["wibAccessTokenAdditionalClaims"] = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenCompanyId"]        = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenCompanyName"]      = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenExp"]              = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenFresh"]            = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenIat"]              = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenJti"]              = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenNbi"]              = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenRoles"]            = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenSub"]              = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenToken"]            = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenType"]             = None                                                              
            self.dictReqHandlerEnv["wibAccessTokenUid"]              = None                                                              

            self.dictReqHandlerEnv["dictWIBRefreshToken"]            = None
            self.dictReqHandlerEnv["wibRefreshTokenExp"]             = None
            self.dictReqHandlerEnv["wibRefreshToken"]                = None

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"
        #
        #   "POST" Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/auth/login/
        #                                   -> {"username":"xxx","password":"yyy"}
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpPostRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "POST"
        #   wibReqURL      = ("https://%s:%s/api/v1/auth/login" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], self.dictPy3GblEnv["sWIBPlatformServerPort"]))
            wibReqURL      = ("https://%s/api/v1/auth/login" % (self.dictPy3GblEnv["sWIBPlatformServerHost"]))
            wibReqDataLoad = {"username"        : self.dictPy3GblEnv["sWIBPlatformUsername"],
                              "password"        : self.dictPy3GblEnv["sWIBPlatformPassword"],
                             }
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "Content-Type"    : "application/json",
                              "cache-control"   : "no-cache",
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "Referer"         : ("https://%s/login" % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }
                             #"Content-Type"    : "application/x-www-form-urlencoded",
                             #"Accept"          : "application/json",

            print("%s Issuing a '%s' to URL [%s] with 'data' of [%s] and header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqDataLoad, wibReqHeaders), flush=True)

        #   async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, data=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:
            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, json=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                    print("")
                    print("%s Response 'json' PRETTY Print:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))

                self.dictReqHandlerEnv["wibReqResponseJson"] = wibReqResponseJson

                if type(wibReqResponseJson) != dict:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object of Type [%s] that is NOT the expected Dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson)))
                    print("", flush=True)

                    return

                self.dictReqHandlerEnv["dictWIBResponseAccess"] = wibReqResponseJson

                if "accessToken" in self.dictReqHandlerEnv["dictWIBResponseAccess"]:

                    self.dictReqHandlerEnv["dictWIBAccessToken"] = self.dictReqHandlerEnv["dictWIBResponseAccess"]["accessToken"]

                    if self.dictReqHandlerEnv["dictWIBAccessToken"]       == None or \
                       type(self.dictReqHandlerEnv["dictWIBAccessToken"]) != dict:

                        self.dictPy3GblEnv["bProcessingError"] = True

                        print("%s The URL Response dictionary key of 'accessToken' has a value of None or is NOT of a Dictionary Type - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                        print("", flush=True)

                        return

                    if "additional_claims" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenAdditionalClaims"] = self.dictReqHandlerEnv["dictWIBAccessToken"]["additional_claims"]

                    if "company_id" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenCompanyId"]        = self.dictReqHandlerEnv["dictWIBAccessToken"]["company_id"]

                    if "company_name" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenCompanyName"]      = self.dictReqHandlerEnv["dictWIBAccessToken"]["company_name"]

                    if "exp" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenExp"]              = self.dictReqHandlerEnv["dictWIBAccessToken"]["exp"]

                    if "fresh" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenFresh"]            = self.dictReqHandlerEnv["dictWIBAccessToken"]["fresh"]

                    if "iat" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenIat"]              = self.dictReqHandlerEnv["dictWIBAccessToken"]["iat"]

                    if "jti" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenJti"]              = self.dictReqHandlerEnv["dictWIBAccessToken"]["jti"]

                    if "nbf" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenNbi"]              = self.dictReqHandlerEnv["dictWIBAccessToken"]["nbf"]

                    if "roles" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenRoles"]            = self.dictReqHandlerEnv["dictWIBAccessToken"]["roles"]

                    if "sub" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenSub"]              = self.dictReqHandlerEnv["dictWIBAccessToken"]["sub"]

                    if "token" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenToken"]            = self.dictReqHandlerEnv["dictWIBAccessToken"]["token"]

                    if "type" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenType"]             = self.dictReqHandlerEnv["dictWIBAccessToken"]["type"]

                    if "uid" in self.dictReqHandlerEnv["dictWIBAccessToken"]:

                        self.dictReqHandlerEnv["wibAccessTokenUid"]              = self.dictReqHandlerEnv["dictWIBAccessToken"]["uid"]

                if "refreshToken" in self.dictReqHandlerEnv["dictWIBResponseAccess"]:

                    self.dictReqHandlerEnv["dictWIBRefreshToken"] = self.dictReqHandlerEnv["dictWIBResponseAccess"]["refreshToken"]

                    if self.dictReqHandlerEnv["dictWIBRefreshToken"]       == None or \
                       type(self.dictReqHandlerEnv["dictWIBRefreshToken"]) != dict:

                        self.dictPy3GblEnv["bProcessingError"] = True

                        print("%s The URL Response dictionary key of 'refreshToken' has a value of None or is NOT of a Dictionary Type - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                        print("", flush=True)

                        return

                    if "exp" in self.dictReqHandlerEnv["dictWIBRefreshToken"]:

                        self.dictReqHandlerEnv["wibRefreshTokenExp"] = self.dictReqHandlerEnv["dictWIBRefreshToken"]["exp"]

                    if "token" in self.dictReqHandlerEnv["dictWIBRefreshToken"]:

                        self.dictReqHandlerEnv["wibRefreshToken"] = self.dictReqHandlerEnv["dictWIBRefreshToken"]["token"]

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned Response value(s) of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print("    Access Token  'additional_claims'  [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenAdditionalClaims"]))
                    print("    Access Token  'company_id'         [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenCompanyId"]))
                    print("    Access Token  'company_name'       [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenCompanyName"]))
                    print("    Access Token  'exp'                [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenExp"]))
                    print("    Access Token  'fresh'              [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenFresh"]))
                    print("    Access Token  'iat'                [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenIat"]))
                    print("    Access Token  'jti'                [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenJti"]))
                    print("    Access Token  'nbf'                [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenNbi"]))
                    print("    Access Token  'roles'              [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenRoles"]))
                    print("    Access Token  'sub'                [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenSub"]))
                    print("    Access Token  'token'              [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenToken"]))
                    print("    Access Token  'type'               [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenType"]))
                    print("    Access Token  'uid'                [%s]..." % (self.dictReqHandlerEnv["wibAccessTokenUid"]))
                    print("")
                    print("    Refresh Token 'exp'                [%s]..." % (self.dictReqHandlerEnv["wibRefreshTokenExp"]))
                    print("    Refresh Token 'token'              [%s]..." % (self.dictReqHandlerEnv["wibRefreshToken"]))
                    print("", flush=True)
                 
                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

                if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

                    self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

                if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
                   len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s 'HttpRequestHandlerClient.__connectHttpClientSession()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__connectHttpClientSession()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __gatherAllWIBPortalData(self) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        try:

        #   self.dictReqHandlerEnv["dictWIBPlatformData"] = {}
            self.dictReqHandlerEnv["dictWIBPlatformData"] = OrderedDict()

            # --------------------------------------------------------------------------------------------------------------
            # <<< Platform -> Dashboard (Statistics: Aggregated & Daily)
            # --------------------------------------------------------------------------------------------------------------
            
            # Retrieve Dashboard/Statistics-Aggregated...

            await self.__retrieveHttpClientStatisticsAggregated()

            if self.dictPy3GblEnv["bProcessingError"] == True:

                print("%s 'HttpRequestHandlerClient.__retrieveHttpClientStatisticsAggregated()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            # Retrieve Dashboard/Statistics-Daily...

            await self.__retrieveHttpClientStatisticsDaily()

            if self.dictPy3GblEnv["bProcessingError"] == True:

                print("%s 'HttpRequestHandlerClient.__retrieveHttpClientStatisticsDaily()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            # --------------------------------------------------------------------------------------------------------------
            # <<< Platform -> Security Center (Incident(s), Vulnerabilities, & Misconfigurations)
            # --------------------------------------------------------------------------------------------------------------
            
            # Retrieve Security-Center/Incident(s)...

            fIncidentsRange = (int(self.dictPy3GblEnv["sWIBIncidentsLimit"]) / self.dictPy3GblEnv["cWIBIncidentsAPIMax"])
            cIncidentsRange = math.ceil(fIncidentsRange)

            print("")
            print("%s 'self.dictPy3GblEnv[\"sWIBIncidentsLimit\"]' is (%d) - 'self.dictPy3GblEnv[\"cWIBIncidentsAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], int(self.dictPy3GblEnv["sWIBIncidentsLimit"]), self.dictPy3GblEnv["cWIBIncidentsAPIMax"]))
            print("%s 'fIncidentsRange'  is (%f) - 'cIncidentsRange' is (%d)..."      % (self.dictPy3GblEnv["sScriptDisp"], fIncidentsRange, cIncidentsRange))

            cIncidentsOffset = 0
            cIncidentsLoop   = 0   

            print("%s <Initial> 'cIncidentsOffset' is (%d) - 'cIncidentsLoop' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cIncidentsOffset, cIncidentsLoop))
            print("", flush=True)

            self.dictReqHandlerEnv["bWIBIncidentsFetchExhausted"] = False

            for cIncidentsIndex in range(cIncidentsRange): 

                cIncidentsLoop += 1   

                print("%s <ForLoop> 'cIncidentsIndex'  is (%d) - 'self.dictPy3GblEnv[\"cWIBIncidentsAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cIncidentsIndex, self.dictPy3GblEnv["cWIBIncidentsAPIMax"]))
                print("%s <ForLoop> 'cIncidentsOffset' is (%d) - 'cIncidentsLoop' is (%d)..."                              % (self.dictPy3GblEnv["sScriptDisp"], cIncidentsOffset, cIncidentsLoop))
                print("", flush=True)

                await self.__retrieveHttpClientIncidents(cincidentsoffset=cIncidentsOffset, cincidentslimit=self.dictPy3GblEnv["cWIBIncidentsAPIMax"])

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidents()' - Loop #(%d) returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"], cIncidentsLoop))
                    print("", flush=True)

                    return

                if self.dictReqHandlerEnv["bWIBIncidentsFetchExhausted"] == True:

                    self.dictPy3GblEnv["bProcessingError"] = False

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidents()' - Loop #(%d) returned a WIB Incident(s) fetch 'exhausted' flag - Stopping the 'fetch' Loop..." % (self.dictPy3GblEnv["sScriptDisp"], cIncidentsLoop))
                    print("", flush=True)

                    break

                cIncidentsOffset += self.dictPy3GblEnv["cWIBIncidentsAPIMax"]

            print("", flush=True)

            if "Incidents" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"Incidents\" in the WIB Platform Data dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            if "items" not in self.dictReqHandlerEnv["dictWIBPlatformData"]["Incidents"]:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"items\" in the WIB Platform Data dictionary key of \"Incidents\" - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            listWIBIncidents = self.dictReqHandlerEnv["dictWIBPlatformData"]["Incidents"]["items"]

            if listWIBIncidents       == None or \
               type(listWIBIncidents) != list:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Platform Data dictionary keys of \"Incidents\" and \"items\" returned a None value or an object that is NOT a List - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            if len(listWIBIncidents) < 1:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Incident(s) \"items\" List is Empty - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            cWIBIncidentItems = 0

            for dictWIBIncidentItem in listWIBIncidents:

                cWIBIncidentItems += 1

                if dictWIBIncidentItem       == None or \
                   type(dictWIBIncidentItem) != dict:

                    continue

                if len(dictWIBIncidentItem) < 1:

                    continue

                if "id" not in dictWIBIncidentItem:

                    continue

                await self.__retrieveHttpClientIncidentDetails(dictwibincidentitem=dictWIBIncidentItem)
             
                if self.dictPy3GblEnv["bProcessingError"] == True:
             
                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidentDetails()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
             
                    return

                await self.__retrieveHttpClientIncidentEvidences(dictwibincidentitem=dictWIBIncidentItem)

                if self.dictPy3GblEnv["bProcessingError"] == True:
             
                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidentEvidences()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
             
                    return

                await self.__retrieveHttpClientIncidentEvidencesForensics(dictwibincidentitem=dictWIBIncidentItem)

                if self.dictPy3GblEnv["bProcessingError"] == True:
             
                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidentEvidencesForensics()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
             
                    return

            # Retrieve Security-Center/Vulnerabilities...

            fVulnerabilitiesRange = (int(self.dictPy3GblEnv["sWIBVulnerabilitiesLimit"]) / self.dictPy3GblEnv["cWIBVulnerabilitiesAPIMax"])
            cVulnerabilitiesRange = math.ceil(fVulnerabilitiesRange)

            print("%s 'self.dictPy3GblEnv[\"sWIBVulnerabilitiesLimit\"]' is (%d) - 'self.dictPy3GblEnv[\"cWIBVulnerabilitiesAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], int(self.dictPy3GblEnv["sWIBVulnerabilitiesLimit"]), self.dictPy3GblEnv["cWIBVulnerabilitiesAPIMax"]))
            print("%s 'fVulnerabilitiesRange'  is (%f) - 'cVulnerabilitiesRange' is (%d)..."      % (self.dictPy3GblEnv["sScriptDisp"], fVulnerabilitiesRange, cVulnerabilitiesRange))

            cVulnerabilitiesOffset = 0
            cVulnerabilitiesLoop   = 0   

            print("%s <Initial> 'cVulnerabilitiesOffset' is (%d) - 'cVulnerabilitiesLoop' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cVulnerabilitiesOffset, cVulnerabilitiesLoop))
            print("", flush=True)

            self.dictReqHandlerEnv["bWIBVulnerabilitiesFetchExhausted"] = False

            for cVulnerabilitiesIndex in range(cVulnerabilitiesRange): 

                cVulnerabilitiesLoop += 1   

                print("")
                print("%s <ForLoop> 'cVulnerabilitiesIndex'  is (%d) - 'self.dictPy3GblEnv[\"cWIBVulnerabilitiesAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cVulnerabilitiesIndex, self.dictPy3GblEnv["cWIBVulnerabilitiesAPIMax"]))
                print("%s <ForLoop> 'cVulnerabilitiesOffset' is (%d) - 'cVulnerabilitiesLoop' is (%d)..."                              % (self.dictPy3GblEnv["sScriptDisp"], cVulnerabilitiesOffset, cVulnerabilitiesLoop))
                print("", flush=True)

                await self.__retrieveHttpClientVulnerabilities(cvulnerabilitiesoffset=cVulnerabilitiesOffset, cvulnerabilitieslimit=self.dictPy3GblEnv["cWIBVulnerabilitiesAPIMax"])

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientVulnerabilities()' - Loop #(%d) returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"], cVulnerabilitiesLoop))
                    print("", flush=True)

                    return

                if self.dictReqHandlerEnv["bWIBVulnerabilitiesFetchExhausted"] == True:

                    self.dictPy3GblEnv["bProcessingError"] = False

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientVulnerabilities()' - Loop #(%d) returned a WIB Incident(s) fetch 'exhausted' flag - Stopping the 'fetch' Loop..." % (self.dictPy3GblEnv["sScriptDisp"], cVulnerabilitiesLoop))
                    print("", flush=True)

                    break

                cVulnerabilitiesOffset += self.dictPy3GblEnv["cWIBVulnerabilitiesAPIMax"]

            print("", flush=True)

            if "Vulnerabilities" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"Vulnerabilities\" in the WIB Platform Data dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            if "items" not in self.dictReqHandlerEnv["dictWIBPlatformData"]["Vulnerabilities"]:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"items\" in the WIB Platform Data dictionary key of \"Vulnerabilities\" - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            listWIBVulnerabilities = self.dictReqHandlerEnv["dictWIBPlatformData"]["Vulnerabilities"]["items"]

            if listWIBVulnerabilities       == None or \
               type(listWIBVulnerabilities) != list:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Platform Data dictionary keys of \"Vulnerabilities\" and \"items\" returned a None value or an object that is NOT a List - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            if len(listWIBVulnerabilities) < 1:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Vulnerabilities \"items\" List is Empty - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            cWIBVulnerabilityItems = 0

            for dictWIBVulnerabilityItem in listWIBVulnerabilities:

                cWIBVulnerabilityItems += 1

                if dictWIBVulnerabilityItem       == None or \
                   type(dictWIBVulnerabilityItem) != dict:

                    continue

                if len(dictWIBVulnerabilityItem) < 1:

                    continue

                if "id" not in dictWIBVulnerabilityItem:

                    continue

                await self.__retrieveHttpClientVulnerabilityDetails(dictwibvulnerabilityitem=dictWIBVulnerabilityItem)

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientVulnerabilityDetails()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))

                    return

            #   await self.__retrieveHttpClientVulnerabilityEvidences(dictwibvulnerabilityitem=dictWIBVulnerabilityItem)
            #
            #   if self.dictPy3GblEnv["bProcessingError"] == True:
            #
            #       print("%s 'HttpRequestHandlerClient.__retrieveHttpClientVulnerabilityEvidences()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            #
            #       return
            #
            #   await self.__retrieveHttpClientVulnerabilityEvidencesForensics(dictwibvulnerabilityitem=dictWIBVulnerabilityItem)
            #
            #   if self.dictPy3GblEnv["bProcessingError"] == True:
            #
            #       print("%s 'HttpRequestHandlerClient.__retrieveHttpClientVulnerabilityEvidencesForensics()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            #
            #       return

            # Retrieve Security-Center/Misconfigurations...

            fMisconfigurationsRange = (int(self.dictPy3GblEnv["sWIBMisconfigurationsLimit"]) / self.dictPy3GblEnv["cWIBMisconfigurationsAPIMax"])
            cMisconfigurationsRange = math.ceil(fMisconfigurationsRange)

            print("")
            print("%s 'self.dictPy3GblEnv[\"sWIBMisconfigurationsLimit\"]' is (%d) - 'self.dictPy3GblEnv[\"cWIBMisconfigurationsAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], int(self.dictPy3GblEnv["sWIBMisconfigurationsLimit"]), self.dictPy3GblEnv["cWIBMisconfigurationsAPIMax"]))
            print("%s 'fMisconfigurationsRange'  is (%f) - 'cMisconfigurationsRange' is (%d)..."      % (self.dictPy3GblEnv["sScriptDisp"], fMisconfigurationsRange, cMisconfigurationsRange))

            cMisconfigurationsOffset = 0
            cMisconfigurationsLoop   = 0   

            print("%s <Initial> 'cMisconfigurationsOffset' is (%d) - 'cMisconfigurationsLoop' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cMisconfigurationsOffset, cMisconfigurationsLoop))
            print("", flush=True)

            self.dictReqHandlerEnv["bWIBMisconfigurationsFetchExhausted"] = False

            for cMisconfigurationsIndex in range(cMisconfigurationsRange): 

                cMisconfigurationsLoop += 1   

                print("%s <ForLoop> 'cMisconfigurationsIndex'  is (%d) - 'self.dictPy3GblEnv[\"cWIBMisconfigurationsAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cMisconfigurationsIndex, self.dictPy3GblEnv["cWIBMisconfigurationsAPIMax"]))
                print("%s <ForLoop> 'cMisconfigurationsOffset' is (%d) - 'cMisconfigurationsLoop' is (%d)..."                              % (self.dictPy3GblEnv["sScriptDisp"], cMisconfigurationsOffset, cMisconfigurationsLoop))
                print("", flush=True)

                await self.__retrieveHttpClientMisconfigurations(cmisconfigurationsoffset=cMisconfigurationsOffset, cmisconfigurationslimit=self.dictPy3GblEnv["cWIBMisconfigurationsAPIMax"])

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientMisconfigurations()' - Loop #(%d) returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"], cMisconfigurationsLoop))
                    print("", flush=True)

                    return

                if self.dictReqHandlerEnv["bWIBMisconfigurationsFetchExhausted"] == True:

                    self.dictPy3GblEnv["bProcessingError"] = False

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientMisconfigurations()' - Loop #(%d) returned a WIB Incident(s) fetch 'exhausted' flag - Stopping the 'fetch' Loop..." % (self.dictPy3GblEnv["sScriptDisp"], cMisconfigurationsLoop))
                    print("", flush=True)

                    break

                cMisconfigurationsOffset += self.dictPy3GblEnv["cWIBMisconfigurationsAPIMax"]

            print("", flush=True)

            if "Misconfigurations" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"Misconfigurations\" in the WIB Platform Data dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            if "items" not in self.dictReqHandlerEnv["dictWIBPlatformData"]["Misconfigurations"]:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"items\" in the WIB Platform Data dictionary key of \"Misconfigurations\" - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            listWIBMisconfigurations = self.dictReqHandlerEnv["dictWIBPlatformData"]["Misconfigurations"]["items"]

            if listWIBMisconfigurations       == None or \
               type(listWIBMisconfigurations) != list:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Platform Data dictionary keys of \"Misconfigurations\" and \"items\" returned a None value or an object that is NOT a List - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            if len(listWIBMisconfigurations) < 1:

            #   self.dictPy3GblEnv["bProcessingError"] = True

            #   print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Misconfigurations \"items\" List is Empty - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Misconfigurations \"items\" List is Empty - Warning!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

            #   return

            cWIBMisconfigurationItems = 0

            for dictWIBMisconfigurationItem in listWIBMisconfigurations:

                cWIBMisconfigurationItems += 1

                if dictWIBMisconfigurationItem       == None or \
                   type(dictWIBMisconfigurationItem) != dict:

                    continue

                if len(dictWIBMisconfigurationItem) < 1:

                    continue

                if "id" not in dictWIBMisconfigurationItem:

                    continue

                await self.__retrieveHttpClientMisconfigurationDetails(dictwibmisconfigurationitem=dictWIBMisconfigurationItem)

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientMisconfigurationDetails()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))

                    return

            #   await self.__retrieveHttpClientMisconfigurationEvidences(dictwibmisconfigurationitem=dictWIBMisconfigurationItem)
            #
            #   if self.dictPy3GblEnv["bProcessingError"] == True:
            #
            #       print("%s 'HttpRequestHandlerClient.__retrieveHttpClientMisconfigurationEvidences()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            #
            #       return
            #
            #   await self.__retrieveHttpClientMisconfigurationEvidencesForensics(dictwibmisconfigurationitem=dictWIBMisconfigurationItem)
            #
            #   if self.dictPy3GblEnv["bProcessingError"] == True:
            #
            #       print("%s 'HttpRequestHandlerClient.__retrieveHttpClientMisconfigurationEvidencesForensics()' - returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            #
            #       return

            # --------------------------------------------------------------------------------------------------------------
            # <<< Platform -> Inventory (Endpoint(s), Hostname(s), & Repositories)
            # --------------------------------------------------------------------------------------------------------------

            # Retrieve Inventory/Endpoint(s)...

            fEndpointsRange = (int(self.dictPy3GblEnv["sWIBEndpointsLimit"]) / self.dictPy3GblEnv["cWIBEndpointsAPIMax"])
            cEndpointsRange = math.ceil(fEndpointsRange)

            print("")
            print("%s 'self.dictPy3GblEnv[\"sWIBEndpointsLimit\"]' is (%d) - 'self.dictPy3GblEnv[\"cWIBEndpointsAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], int(self.dictPy3GblEnv["sWIBEndpointsLimit"]), self.dictPy3GblEnv["cWIBEndpointsAPIMax"]))
            print("%s 'fEndpointsRange'  is (%f) - 'cEndpointsRange' is (%d)..."      % (self.dictPy3GblEnv["sScriptDisp"], fEndpointsRange, cEndpointsRange))

            cEndpointsOffset = 0
            cEndpointsLoop   = 0   

            print("%s <Initial> 'cEndpointsOffset' is (%d) - 'cEndpointsLoop' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cEndpointsOffset, cEndpointsLoop))
            print("", flush=True)

            self.dictReqHandlerEnv["bWIBEndpointsFetchExhausted"] = False

            for cEndpointsIndex in range(cEndpointsRange): 

                cEndpointsLoop += 1   

                print("%s <ForLoop> 'cEndpointsIndex'  is (%d) - 'self.dictPy3GblEnv[\"cWIBEndpointsAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cEndpointsIndex, self.dictPy3GblEnv["cWIBEndpointsAPIMax"]))
                print("%s <ForLoop> 'cEndpointsOffset' is (%d) - 'cEndpointsLoop' is (%d)..."                              % (self.dictPy3GblEnv["sScriptDisp"], cEndpointsOffset, cEndpointsLoop))
                print("", flush=True)

                await self.__retrieveHttpClientEndpoints(cendpointsoffset=cEndpointsOffset, cendpointslimit=self.dictPy3GblEnv["cWIBEndpointsAPIMax"])

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientEndpoints()' - Loop #(%d) returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"], cEndpointsLoop))
                    print("", flush=True)

                    return

                if self.dictReqHandlerEnv["bWIBEndpointsFetchExhausted"] == True:

                    self.dictPy3GblEnv["bProcessingError"] = False

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientEndpoints()' - Loop #(%d) returned a WIB Endpoint(s) fetch 'exhausted' flag - Stopping the 'fetch' Loop..." % (self.dictPy3GblEnv["sScriptDisp"], cEndpointsLoop))
                    print("", flush=True)

                    break

                cEndpointsOffset += self.dictPy3GblEnv["cWIBEndpointsAPIMax"]

            print("", flush=True)

            if "Endpoints" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"Endpoints\" in the WIB Platform Data dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            if "items" not in self.dictReqHandlerEnv["dictWIBPlatformData"]["Endpoints"]:
         
                self.dictPy3GblEnv["bProcessingError"] = True
         
                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"items\" in the WIB Platform Data dictionary key of \"Endpoints\" - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)
         
                return
         
            listWIBEndpoints = self.dictReqHandlerEnv["dictWIBPlatformData"]["Endpoints"]["items"]
         
            if listWIBEndpoints       == None or \
               type(listWIBEndpoints) != list:
         
                self.dictPy3GblEnv["bProcessingError"] = True
         
                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Platform Data dictionary keys of \"Endpoints\" and \"items\" returned a None value or an object that is NOT a List - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)
         
                return
         
            if len(listWIBEndpoints) < 1:
         
                self.dictPy3GblEnv["bProcessingError"] = True
         
                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Endpoint(s) \"items\" List is Empty - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)
         
                return

            # Retrieve Inventory/Hostname(s)...

            fHostnamesRange = (int(self.dictPy3GblEnv["sWIBHostnamesLimit"]) / self.dictPy3GblEnv["cWIBHostnamesAPIMax"])
            cHostnamesRange = math.ceil(fHostnamesRange)

            print("")
            print("%s 'self.dictPy3GblEnv[\"sWIBHostnamesLimit\"]' is (%d) - 'self.dictPy3GblEnv[\"cWIBHostnamesAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], int(self.dictPy3GblEnv["sWIBHostnamesLimit"]), self.dictPy3GblEnv["cWIBHostnamesAPIMax"]))
            print("%s 'fHostnamesRange'  is (%f) - 'cHostnamesRange' is (%d)..."      % (self.dictPy3GblEnv["sScriptDisp"], fHostnamesRange, cHostnamesRange))

            cHostnamesOffset = 0
            cHostnamesLoop   = 0   

            print("%s <Initial> 'cHostnamesOffset' is (%d) - 'cHostnamesLoop' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cHostnamesOffset, cHostnamesLoop))
            print("", flush=True)

            self.dictReqHandlerEnv["bWIBHostnamesFetchExhausted"] = False

            for cHostnamesIndex in range(cHostnamesRange): 

                cHostnamesLoop += 1   

                print("%s <ForLoop> 'cHostnamesIndex'  is (%d) - 'self.dictPy3GblEnv[\"cWIBHostnamesAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cHostnamesIndex, self.dictPy3GblEnv["cWIBHostnamesAPIMax"]))
                print("%s <ForLoop> 'cHostnamesOffset' is (%d) - 'cHostnamesLoop' is (%d)..."                              % (self.dictPy3GblEnv["sScriptDisp"], cHostnamesOffset, cHostnamesLoop))
                print("", flush=True)

                await self.__retrieveHttpClientHostnames(chostnamesoffset=cHostnamesOffset, chostnameslimit=self.dictPy3GblEnv["cWIBHostnamesAPIMax"])

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientHostnames()' - Loop #(%d) returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"], cHostnamesLoop))
                    print("", flush=True)

                    return

                if self.dictReqHandlerEnv["bWIBHostnamesFetchExhausted"] == True:

                    self.dictPy3GblEnv["bProcessingError"] = False

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientHostnames()' - Loop #(%d) returned a WIB Hostname(s) fetch 'exhausted' flag - Stopping the 'fetch' Loop..." % (self.dictPy3GblEnv["sScriptDisp"], cHostnamesLoop))
                    print("", flush=True)

                    break

                cHostnamesOffset += self.dictPy3GblEnv["cWIBHostnamesAPIMax"]

            print("", flush=True)

            if "Hostnames" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"Hostnames\" in the WIB Platform Data dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            if "items" not in self.dictReqHandlerEnv["dictWIBPlatformData"]["Hostnames"]:
         
                self.dictPy3GblEnv["bProcessingError"] = True
         
                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"items\" in the WIB Platform Data dictionary key of \"Hostnames\" - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)
         
                return
         
            listWIBHostnames = self.dictReqHandlerEnv["dictWIBPlatformData"]["Hostnames"]["items"]
         
            if listWIBHostnames       == None or \
               type(listWIBHostnames) != list:
         
                self.dictPy3GblEnv["bProcessingError"] = True
         
                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Platform Data dictionary keys of \"Hostnames\" and \"items\" returned a None value or an object that is NOT a List - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)
         
                return
         
            if len(listWIBHostnames) < 1:
         
                self.dictPy3GblEnv["bProcessingError"] = True
         
                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Hostname(s) \"items\" List is Empty - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)
         
                return

            # Retrieve Inventory/Repositories...

            fRepositoriesRange = (int(self.dictPy3GblEnv["sWIBRepositoriesLimit"]) / self.dictPy3GblEnv["cWIBRepositoriesAPIMax"])
            cRepositoriesRange = math.ceil(fRepositoriesRange)

            print("")
            print("%s 'self.dictPy3GblEnv[\"sWIBRepositoriesLimit\"]' is (%d) - 'self.dictPy3GblEnv[\"cWIBRepositoriesAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], int(self.dictPy3GblEnv["sWIBRepositoriesLimit"]), self.dictPy3GblEnv["cWIBRepositoriesAPIMax"]))
            print("%s 'fRepositoriesRange'  is (%f) - 'cRepositoriesRange' is (%d)..."      % (self.dictPy3GblEnv["sScriptDisp"], fRepositoriesRange, cRepositoriesRange))

            cRepositoriesOffset = 0
            cRepositoriesLoop   = 0   

            print("%s <Initial> 'cRepositoriesOffset' is (%d) - 'cRepositoriesLoop' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cRepositoriesOffset, cRepositoriesLoop))
            print("", flush=True)

            self.dictReqHandlerEnv["bWIBRepositoriesFetchExhausted"] = False

            for cRepositoriesIndex in range(cRepositoriesRange): 

                cRepositoriesLoop += 1   

                print("%s <ForLoop> 'cRepositoriesIndex'  is (%d) - 'self.dictPy3GblEnv[\"cWIBRepositoriesAPIMax\"]' is (%d)..." % (self.dictPy3GblEnv["sScriptDisp"], cRepositoriesIndex, self.dictPy3GblEnv["cWIBRepositoriesAPIMax"]))
                print("%s <ForLoop> 'cRepositoriesOffset' is (%d) - 'cRepositoriesLoop' is (%d)..."                              % (self.dictPy3GblEnv["sScriptDisp"], cRepositoriesOffset, cRepositoriesLoop))
                print("", flush=True)

                await self.__retrieveHttpClientRepositories(crepositoriesoffset=cRepositoriesOffset, crepositorieslimit=self.dictPy3GblEnv["cWIBRepositoriesAPIMax"])

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientRepositories()' - Loop #(%d) returned a 'processing' error flag - Error!" % (self.dictPy3GblEnv["sScriptDisp"], cRepositoriesLoop))
                    print("", flush=True)

                    return

                if self.dictReqHandlerEnv["bWIBRepositoriesFetchExhausted"] == True:

                    self.dictPy3GblEnv["bProcessingError"] = False

                    print("%s 'HttpRequestHandlerClient.__retrieveHttpClientRepositories()' - Loop #(%d) returned a WIB Repositories fetch 'exhausted' flag - Stopping the 'fetch' Loop..." % (self.dictPy3GblEnv["sScriptDisp"], cRepositoriesLoop))
                    print("", flush=True)

                    break

                cRepositoriesOffset += self.dictPy3GblEnv["cWIBRepositoriesAPIMax"]

            print("", flush=True)

            if "Repositories" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"Repositories\" in the WIB Platform Data dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

            if "items" not in self.dictReqHandlerEnv["dictWIBPlatformData"]["Repositories"]:
         
                self.dictPy3GblEnv["bProcessingError"] = True
         
                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - there is no key of \"items\" in the WIB Platform Data dictionary key of \"Repositories\" - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)
         
                return
         
            listWIBRepositories = self.dictReqHandlerEnv["dictWIBPlatformData"]["Repositories"]["items"]
         
            if listWIBRepositories       == None or \
               type(listWIBRepositories) != list:
         
                self.dictPy3GblEnv["bProcessingError"] = True
         
                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Platform Data dictionary keys of \"Repositories\" and \"items\" returned a None value or an object that is NOT a List - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)
         
                return
         
            if len(listWIBRepositories) < 1:
         
                self.dictPy3GblEnv["bProcessingError"] = True
         
                print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - the WIB Hostname(s) \"items\" List is Empty - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)
         
                return

            # --------------------------------------------------------------------------------------------------------------
            # <<< Platform -> ...(optional) Recap...
            # --------------------------------------------------------------------------------------------------------------
            
            # If 'Verbose', recap the WIB Platform data (raw JSON)...

            if self.dictPy3GblEnv["bVerbose"] == True:

                print("%s WIB Platform data - 'json' PRETTY Print (Final Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                print(json.dumps(self.dictReqHandlerEnv["dictWIBPlatformData"], indent=4))
                print("", flush=True)

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__gatherAllWIBPortalData()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

            return

        return

    async def __retrieveHttpClientStatisticsAggregated(self) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientStatisticsAggregated()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            print("%s The URL Request 'startDate' is [%s] and 'endDate' is [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], self.dictPy3GblEnv["sWIBStatisticsStartDate"], self.dictPy3GblEnv["sWIBStatisticsEndDate"]))
            print("", flush=True)

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"
        #
        #   "POST" Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/statistics/aggregated/
        #                                   -> {"startDate":"2023-08-26","endDate":"2023-09-02"}
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpPostRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "POST"
            wibReqURL      = ("https://%s/api/v1/statistics/aggregated/" % (self.dictPy3GblEnv["sWIBPlatformServerHost"]))
            wibReqDataLoad = {"startDate"       : self.dictPy3GblEnv["sWIBStatisticsStartDate"],
                              "endDate"         : self.dictPy3GblEnv["sWIBStatisticsEndDate"],
                             }
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "Content-Type"    : "application/json",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with 'data' of [%s] and header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqDataLoad, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, json=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                    print("")
                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                self.dictReqHandlerEnv["wibReqResponseJson"] = wibReqResponseJson
            
                if type(wibReqResponseJson) != dict:
            
                    self.dictPy3GblEnv["bProcessingError"] = True
            
                    print("%s The URL Request returned a Response 'json' object of Type [%s] that is NOT the expected Dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson)))
                    print("", flush=True)
            
                    return
            
                self.dictReqHandlerEnv["dictWIBPlatformData"]["StatisticsAggregated"] = wibReqResponseJson
            
                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Dictionary of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(self.dictReqHandlerEnv["dictWIBPlatformData"]["StatisticsAggregated"], indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientStatisticsAggregated()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientStatisticsDaily(self) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientStatisticsDaily()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            print("%s The URL Request 'startDate' is [%s] and 'endDate' is [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], self.dictPy3GblEnv["sWIBStatisticsStartDate"], self.dictPy3GblEnv["sWIBStatisticsEndDate"]))
            print("", flush=True)

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"
        #
        #   "POST" Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/statistics/daily/
        #                                   -> {"startDate":"2023-08-26","endDate":"2023-09-02"}
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpPostRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "POST"
            wibReqURL      = ("https://%s/api/v1/statistics/daily/" % (self.dictPy3GblEnv["sWIBPlatformServerHost"]))
            wibReqDataLoad = {"startDate"       : self.dictPy3GblEnv["sWIBStatisticsStartDate"],
                              "endDate"         : self.dictPy3GblEnv["sWIBStatisticsEndDate"],
                             }
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "Content-Type"    : "application/json",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with 'data' of [%s] and header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqDataLoad, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, json=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                    print("")
                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                self.dictReqHandlerEnv["wibReqResponseJson"] = wibReqResponseJson
            
                if type(wibReqResponseJson) != list:
            
                    self.dictPy3GblEnv["bProcessingError"] = True
            
                    print("%s The URL Request returned a Response 'json' object of Type [%s] that is NOT the expected List - Error!" % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson)))
                    print("", flush=True)
            
                    return
            
                self.dictReqHandlerEnv["dictWIBPlatformData"]["StatisticsDaily"] = wibReqResponseJson
            
                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a List of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(self.dictReqHandlerEnv["dictWIBPlatformData"]["StatisticsDaily"], indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientStatisticsDaily()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientIncidents(self, cincidentsoffset=0, cincidentslimit=0) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidents()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        cIncidentsOffset = cincidentsoffset

        if cIncidentsOffset < 0:

            cIncidentsOffset = 0

        cIncidentsLimit = cincidentslimit

        if cIncidentsLimit > self.dictPy3GblEnv["cWIBIncidentsAPIMax"]:

            cIncidentsLimit = self.dictPy3GblEnv["cWIBIncidentsAPIMax"]

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            print("%s The URL Request 'sWIBIncidentsStartTime' is [%s] and 'sWIBIncidentsEndTime' is [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], self.dictPy3GblEnv["sWIBIncidentsStartTime"], self.dictPy3GblEnv["sWIBIncidentsEndTime"]))
            print("%s The URL Request 'cIncidentsOffset' is [%d] and 'cIncidentsLimit' is [%d]..."            % (self.dictPy3GblEnv["sScriptDisp"], cIncidentsOffset, cIncidentsLimit))
            print("", flush=True)

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"                
        #
        #   "POST" Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/incident?offset=0&limit=50
        #                                   -> {"sortBy":[{"key":"LAST_ACTIVITY", "direction":"DESC"}],"muted":False} -or- 
        #                             -or-  -> {"startTime":"2023-08-05T21:11:28.425Z",
        #                                       "endTime":"2023-09-04T16:11:28.425Z",
        #                                       "sortBy":[{"key":"LAST_ACTIVITY",
        #                                                  "direction":"DESC"}],
        #                                       "muted":false}
        #                             -or-  -> {"startTime":"2023-08-05T21:11:28.425Z",
        #                                       "endTime":"2023-09-04T16:11:28.425Z",
        #                                       "severity":["CRITICAL"],
        #                                       "sortBy":[{"key":"LAST_ACTIVITY",
        #                                                  "direction":"DESC"}],
        #                                       "muted":false}
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpPostRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "POST"
            wibReqURL      = ("https://%s/api/v1/incident?offset=%d&limit=%d" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], cIncidentsOffset, cIncidentsLimit))
            wibReqDataLoad = {"startTime"       : self.dictPy3GblEnv["sWIBIncidentsStartTime"],
                              "endTime"         : self.dictPy3GblEnv["sWIBIncidentsEndTime"],
                              "severity"        : self.dictPy3GblEnv["listWIBIncidentsSeverity"],
                              "sortBy"          : [{"key"       : "LAST_ACTIVITY",
                                                    "direction" : "DESC",
                                                   }
                                                  ],
                              "muted"           : False,
                             }
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "Content-Type"    : "application/json",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with 'data' of [%s] and header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqDataLoad, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, json=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                    print("")
                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                self.dictReqHandlerEnv["wibReqResponseJson"] = wibReqResponseJson
            
                if type(wibReqResponseJson) != dict:
            
                    self.dictPy3GblEnv["bProcessingError"] = True
            
                    print("%s The URL Request returned a Response 'json' object of Type [%s] that is NOT the expected Dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson)))
                    print("", flush=True)
            
                    return
            
                dictWIBResponseIncidents = wibReqResponseJson
            
                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Dictionary of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(dictWIBResponseIncidents, indent=4))
                    print("", flush=True)

                listWIBResponseIncidents = []

                if "items" in dictWIBResponseIncidents:

                    listWIBResponseIncidents = dictWIBResponseIncidents["items"]

                    if listWIBResponseIncidents       == None or \
                       type(listWIBResponseIncidents) != list:

                        self.dictPy3GblEnv["bProcessingError"] = True

                        print("%s The URL Response dictionary key of 'items' (Incident(s)) has a value of None or is NOT of a List Type - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                        print("", flush=True)

                        return

                if "Incidents" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:

                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Incidents"]          = dictWIBResponseIncidents
                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Incidents"]["items"] = []

                print("%s Extending the 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"][\"Incidents\"][\"items\"]' List with (%d) item(s)..." % (self.dictPy3GblEnv["sScriptDisp"], len(listWIBResponseIncidents)))
                print("", flush=True)

                self.dictReqHandlerEnv["dictWIBPlatformData"]["Incidents"]["items"].extend(listWIBResponseIncidents)

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a List of Incident(s) of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(listWIBResponseIncidents, indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

                if len(listWIBResponseIncidents) < 1:

                    self.dictReqHandlerEnv["bWIBIncidentsFetchExhausted"] = True

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidents()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientIncidentDetails(self, dictwibincidentitem=None) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidentEvidences()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        dictWIBIncident = dictwibincidentitem

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            sWIBIncidentId = None

            if "id" in dictWIBIncident:

                sWIBIncidentId = dictWIBIncident["id"]

                if sWIBIncidentId != None:

                    sWIBIncidentId = sWIBIncidentId.strip()

                if sWIBIncidentId == None or \
                   len(sWIBIncidentId) < 1:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The Incident dictionary has a key of 'id' with a value of None or Empty - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

            else:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s The Incident dictionary does NOT have a key of 'id' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"
        #
        #   "GET" Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/incident/{incidentId}
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpGetRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "GET"
            wibReqURL      = ("https://%s/api/v1/incident/%s" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], sWIBIncidentId))
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                dictWIBIncident["IncidentDetails"] = wibReqResponseJson

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                    print("")
                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidentDetails()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientIncidentEvidences(self, dictwibincidentitem=None) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidentEvidences()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        dictWIBIncident = dictwibincidentitem

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            sWIBIncidentId = None

            if "id" in dictWIBIncident:

                sWIBIncidentId = dictWIBIncident["id"]

                if sWIBIncidentId != None:

                    sWIBIncidentId = sWIBIncidentId.strip()

                if sWIBIncidentId == None or \
                   len(sWIBIncidentId) < 1:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The Incident dictionary has a key of 'id' with a value of None or Empty - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

            else:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s The Incident dictionary does NOT have a key of 'id' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"
        #
        #   "Get"  Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/evidences/{incidentId}?offset=0&limit=1 -or-
        #   "Post" Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/evidences/{incidentId}/search?offset=0&limit=1
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpPostRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "POST"
        #   wibReqURL      = ("https://%s/api/v1/evidences/%s?offset=0&limit=1" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], sWIBIncidentId))
            wibReqURL      = ("https://%s/api/v1/evidences/%s/search?offset=0&limit=1" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], sWIBIncidentId))
            wibReqDataLoad = {
                             }
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

        #   print("%s Issuing a '%s' to URL [%s] with header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqHeaders), flush=True)
            print("%s Issuing a '%s' to URL [%s] with 'data' of [%s] and header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqDataLoad, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, json=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:
        #   async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                print("")

                dictWIBIncident["IncidentEvidences"] = wibReqResponseJson

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidentEvidences()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientIncidentEvidencesForensics(self, dictwibincidentitem=None) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidentEvidencesForensics()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        dictWIBIncident = dictwibincidentitem

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            sWIBIncidentId = None

            if "id" in dictWIBIncident:

                sWIBIncidentId = dictWIBIncident["id"]

                if sWIBIncidentId != None:

                    sWIBIncidentId = sWIBIncidentId.strip()

                if sWIBIncidentId == None or \
                   len(sWIBIncidentId) < 1:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The Incident dictionary has a key of 'id' with a value of None or Empty - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

            else:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s The Incident dictionary does NOT have a key of 'id' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"
        #
        #   "Post" Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/evidences/{incidentId}/search?offset=0&limit=100
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpPostRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "POST"
            wibReqURL      = ("https://%s/api/v1/evidences/%s/search?offset=0&limit=100" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], sWIBIncidentId))
            wibReqDataLoad = {
                             }
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with 'data' of [%s] and header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqDataLoad, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, json=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                print("")

                dictWIBIncident["IncidentEvidencesForensics"] = wibReqResponseJson

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientIncidentEvidencesForensics()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientVulnerabilities(self, cvulnerabilitiesoffset=0, cvulnerabilitieslimit=0) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientVulnerabilities()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        cVulnerabilitiesOffset = cvulnerabilitiesoffset

        if cVulnerabilitiesOffset < 0:

            cVulnerabilitiesOffset = 0

        cVulnerabilitiesLimit = cvulnerabilitieslimit

        if cVulnerabilitiesLimit > self.dictPy3GblEnv["cWIBVulnerabilitiesAPIMax"]:

            cVulnerabilitiesLimit = self.dictPy3GblEnv["cWIBVulnerabilitiesAPIMax"]

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            print("%s The URL Request 'sWIBVulnerabilitiesStartTime' is [%s] and 'sWIBVulnerabilitiesEndTime' is [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], self.dictPy3GblEnv["sWIBVulnerabilitiesStartTime"], self.dictPy3GblEnv["sWIBVulnerabilitiesEndTime"]))
            print("%s The URL Request 'cVulnerabilitiesOffset' is [%d] and 'cVulnerabilitiesLimit' is [%d]..."            % (self.dictPy3GblEnv["sScriptDisp"], cVulnerabilitiesOffset, cVulnerabilitiesLimit))
            print("", flush=True)

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"                
        #
        #   "POST" Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/vulnerabilities/search?offset=0&limit=50
        #                                   -> {"startTime":"2023-10-25T01:47:21.593Z",
        #                                       "endTime":"2023-10-31T20:47:21.593Z",
        #                                       "excludeOwaspType":["API7_2023_SECURITY_MISCONFIGURATION"],
        #                                       "sortBy":[{"key":"SEVERITY",
        #                                                  "direction":"DESC"}],
        #                                       "muted":false}
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpPostRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "POST"
            wibReqURL      = ("https://%s/api/v1/vulnerabilities/search?offset=%d&limit=%d" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], cVulnerabilitiesOffset, cVulnerabilitiesLimit))
            wibReqDataLoad = {"startTime"       : self.dictPy3GblEnv["sWIBVulnerabilitiesStartTime"],
                              "endTime"         : self.dictPy3GblEnv["sWIBVulnerabilitiesEndTime"],
                              "excludeOwaspType": ["API7_2023_SECURITY_MISCONFIGURATION"],
                              "severity"        : self.dictPy3GblEnv["listWIBVulnerabilitiesSeverity"],
                              "sortBy"          : [{"key"       : "SEVERITY",
                                                    "direction" : "DESC",
                                                   }
                                                  ],
                              "muted"           : False,
                             }
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "Content-Type"    : "application/json",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with 'data' of [%s] and header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqDataLoad, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, json=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                    print("")
                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                self.dictReqHandlerEnv["wibReqResponseJson"] = wibReqResponseJson
            
                if type(wibReqResponseJson) != dict:
            
                    self.dictPy3GblEnv["bProcessingError"] = True
            
                    print("%s The URL Request returned a Response 'json' object of Type [%s] that is NOT the expected Dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson)))
                    print("", flush=True)
            
                    return
            
                dictWIBResponseVulnerabilities = wibReqResponseJson
            
                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Dictionary of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(dictWIBResponseVulnerabilities, indent=4))
                    print("", flush=True)

                listWIBResponseVulnerabilities = []

                if "items" in dictWIBResponseVulnerabilities:

                    listWIBResponseVulnerabilities = dictWIBResponseVulnerabilities["items"]

                    if listWIBResponseVulnerabilities       == None or \
                       type(listWIBResponseVulnerabilities) != list:

                        self.dictPy3GblEnv["bProcessingError"] = True

                        print("%s The URL Response dictionary key of 'items' (Vulnerability(s)) has a value of None or is NOT of a List Type - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                        print("", flush=True)

                        return

                if "Vulnerabilities" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:

                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Vulnerabilities"]          = dictWIBResponseVulnerabilities
                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Vulnerabilities"]["items"] = []

                print("%s Extending the 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"][\"Vulnerabilities\"][\"items\"]' List with (%d) item(s)..." % (self.dictPy3GblEnv["sScriptDisp"], len(listWIBResponseVulnerabilities)))
                print("", flush=True)

                self.dictReqHandlerEnv["dictWIBPlatformData"]["Vulnerabilities"]["items"].extend(listWIBResponseVulnerabilities)

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a List of Vulnerability(s) of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(listWIBResponseVulnerabilities, indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

                if len(listWIBResponseVulnerabilities) < 1:

                    self.dictReqHandlerEnv["bWIBVulnerabilitiesFetchExhausted"] = True

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientVulnerabilities()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientVulnerabilityDetails(self, dictwibvulnerabilityitem=None) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientVulnerabilityEvidences()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        dictWIBVulnerability = dictwibvulnerabilityitem

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            sWIBVulnerabilityId = None

            if "id" in dictWIBVulnerability:

                sWIBVulnerabilityId = dictWIBVulnerability["id"]

                if sWIBVulnerabilityId != None:

                    sWIBVulnerabilityId = sWIBVulnerabilityId.strip()

                if sWIBVulnerabilityId == None or \
                   len(sWIBVulnerabilityId) < 1:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The Vulnerability dictionary has a key of 'id' with a value of None or Empty - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

            else:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s The Vulnerability dictionary does NOT have a key of 'id' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"
        #
        #   "GET" Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/vulnerabilities/{vulnerabilityId}
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpGetRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "GET"
            wibReqURL      = ("https://%s/api/v1/vulnerabilities/%s" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], sWIBVulnerabilityId))
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                dictWIBVulnerability["VulnerabilityDetails"] = wibReqResponseJson

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                    print("")
                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientVulnerabilityDetails()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientMisconfigurations(self, cmisconfigurationsoffset=0, cmisconfigurationslimit=0) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientMisconfigurations()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        cMisconfigurationsOffset = cmisconfigurationsoffset

        if cMisconfigurationsOffset < 0:

            cMisconfigurationsOffset = 0

        cMisconfigurationsLimit = cmisconfigurationslimit

        if cMisconfigurationsLimit > self.dictPy3GblEnv["cWIBMisconfigurationsAPIMax"]:

            cMisconfigurationsLimit = self.dictPy3GblEnv["cWIBMisconfigurationsAPIMax"]

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            print("%s The URL Request 'sWIBMisconfigurationsStartTime' is [%s] and 'sWIBMisconfigurationsEndTime' is [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], self.dictPy3GblEnv["sWIBMisconfigurationsStartTime"], self.dictPy3GblEnv["sWIBMisconfigurationsEndTime"]))
            print("%s The URL Request 'cMisconfigurationsOffset' is [%d] and 'cMisconfigurationsLimit' is [%d]..."            % (self.dictPy3GblEnv["sScriptDisp"], cMisconfigurationsOffset, cMisconfigurationsLimit))
            print("", flush=True)

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"                
        #
        #   "POST" Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/vulnerabilities/hostnames/search?offset=0&limit=20
        #                                   -> {"startTime":"2023-10-25T01:47:21.593Z",
        #                                       "endTime":"2023-10-31T20:47:21.593Z",
        #                                       "sortBy":[{"key":"VULNERABILITY_SUB_TYPE",
        #                                                  "direction":"ASC"}]}
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpPostRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "POST"
            wibReqURL      = ("https://%s/api/v1/vulnerabilities/hostnames/search?offset=%d&limit=%d" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], cMisconfigurationsOffset, cMisconfigurationsLimit))
            wibReqDataLoad = {"startTime"       : self.dictPy3GblEnv["sWIBMisconfigurationsStartTime"],
                              "endTime"         : self.dictPy3GblEnv["sWIBMisconfigurationsEndTime"],
                              "sortBy"          : [{"key"       : "VULNERABILITY_SUB_TYPE",
                                                    "direction" : "ASC",
                                                   }
                                                  ]
                             }
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "Content-Type"    : "application/json",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with 'data' of [%s] and header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqDataLoad, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, json=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                # if self.dictPy3GblEnv["bVerbose"] == True:

                print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                print("")
                print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                print(json.dumps(wibReqResponseJson, indent=4))
                print("", flush=True)

                self.dictReqHandlerEnv["wibReqResponseJson"] = wibReqResponseJson
            
                if type(wibReqResponseJson) != dict:
            
                    self.dictPy3GblEnv["bProcessingError"] = True
            
                    print("%s The URL Request returned a Response 'json' object of Type [%s] that is NOT the expected Dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson)))
                    print("", flush=True)
            
                    return
            
                dictWIBResponseMisconfigurations = wibReqResponseJson
            
                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Dictionary of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(dictWIBResponseMisconfigurations, indent=4))
                    print("", flush=True)

                listWIBResponseMisconfigurations = []

                if "items" in dictWIBResponseMisconfigurations:

                    listWIBResponseMisconfigurations = dictWIBResponseMisconfigurations["items"]

                    if listWIBResponseMisconfigurations       == None or \
                       type(listWIBResponseMisconfigurations) != list:

                        self.dictPy3GblEnv["bProcessingError"] = True

                        print("%s The URL Response dictionary key of 'items' (Misconfiguration(s)) has a value of None or is NOT of a List Type - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                        print("", flush=True)

                        return

                if "Misconfigurations" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:

                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Misconfigurations"]          = dictWIBResponseMisconfigurations
                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Misconfigurations"]["items"] = []

                print("%s Extending the 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"][\"Misconfigurations\"][\"items\"]' List with (%d) item(s)..." % (self.dictPy3GblEnv["sScriptDisp"], len(listWIBResponseMisconfigurations)))
                print("", flush=True)

                self.dictReqHandlerEnv["dictWIBPlatformData"]["Misconfigurations"]["items"].extend(listWIBResponseMisconfigurations)

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a List of Misconfiguration(s) of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(listWIBResponseMisconfigurations, indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

                if len(listWIBResponseMisconfigurations) < 1:

                    self.dictReqHandlerEnv["bWIBMisconfigurationsFetchExhausted"] = True

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientMisconfigurations()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientMisconfigurationDetails(self, dictwibmisconfigurationitem=None) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientMisconfigurationEvidences()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        dictWIBMisconfiguration = dictwibmisconfigurationitem

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            sWIBMisconfigurationId = None

            if "id" in dictWIBMisconfiguration:

                sWIBMisconfigurationId = dictWIBMisconfiguration["id"]

                if sWIBMisconfigurationId != None:

                    sWIBMisconfigurationId = sWIBMisconfigurationId.strip()

                if sWIBMisconfigurationId == None or \
                   len(sWIBMisconfigurationId) < 1:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The Misconfiguration dictionary has a key of 'id' with a value of None or Empty - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

            else:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s The Misconfiguration dictionary does NOT have a key of 'id' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                print("", flush=True)

                return

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"
        #
        #   "GET" Response 'Ok' (200): https://wib-product.wib-security.com/api/v1/vulnerabilities/hostnames/{misconfigurationId}
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpGetRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "GET"
            wibReqURL      = ("https://%s/api/v1/vulnerabilities/hostnames/%s" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], sWIBMisconfigurationId))
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                dictWIBMisconfiguration["MisconfigurationDetails"] = wibReqResponseJson

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                    print("")
                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientMisconfigurationDetails()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientEndpoints(self, cendpointsoffset=0, cendpointslimit=0) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientEndpoints()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        cEndpointsOffset = cendpointsoffset

        if cEndpointsOffset < 0:

            cEndpointsOffset = 0

        cEndpointsLimit = cendpointslimit

        if cEndpointsLimit > self.dictPy3GblEnv["cWIBEndpointsAPIMax"]:

            cEndpointsLimit = self.dictPy3GblEnv["cWIBEndpointsAPIMax"]

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            print("%s The URL Request 'cEndpointsOffset' is [%d] and 'cEndpointsLimit' is [%d]..." % (self.dictPy3GblEnv["sScriptDisp"], cEndpointsOffset, cEndpointsLimit))
            print("", flush=True)

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"                
        #
        #   "POST" Response 'Ok' (200): https://wib-product.wib-security.com/api/v2/inventory/endpoints/search?offset=0&limit=50
        #                                   -> {"sortBy":[{"key":"RISK_SCORE", "direction":"DESC"}]} 
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpPostRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "POST"
            wibReqURL      = ("https://%s/api/v2/inventory/endpoints/search?offset=%d&limit=%d" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], cEndpointsOffset, cEndpointsLimit))
            wibReqDataLoad = {"sortBy"          : [{"key"       : "RISK_SCORE",
                                                    "direction" : "DESC",
                                                   }
                                                  ]
                             }
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "Content-Type"    : "application/json",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with 'data' of [%s] and header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqDataLoad, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, json=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                    print("")
                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                self.dictReqHandlerEnv["wibReqResponseJson"] = wibReqResponseJson
            
                if type(wibReqResponseJson) != dict:
            
                    self.dictPy3GblEnv["bProcessingError"] = True
            
                    print("%s The URL Request returned a Response 'json' object of Type [%s] that is NOT the expected Dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson)))
                    print("", flush=True)
            
                    return
            
                dictWIBResponseEndpoints = wibReqResponseJson
            
                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Dictionary of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(dictWIBResponseEndpoints, indent=4))
                    print("", flush=True)

                listWIBResponseEndpoints = []
            
                if "items" in dictWIBResponseEndpoints:
             
                    listWIBResponseEndpoints = dictWIBResponseEndpoints["items"]
             
                    if listWIBResponseEndpoints       == None or \
                       type(listWIBResponseEndpoints) != list:
             
                        self.dictPy3GblEnv["bProcessingError"] = True
             
                        print("%s The URL Response dictionary key of 'items' (Endpoints(s)) has a value of None or is NOT of a List Type - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                        print("", flush=True)
             
                        return
             
                if "Endpoints" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:
             
                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Endpoints"]          = dictWIBResponseEndpoints
                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Endpoints"]["items"] = []
             
                print("%s Extending the 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"][\"Endpoints\"][\"items\"]' List with (%d) item(s)..." % (self.dictPy3GblEnv["sScriptDisp"], len(listWIBResponseEndpoints)))
                print("", flush=True)
             
                self.dictReqHandlerEnv["dictWIBPlatformData"]["Endpoints"]["items"].extend(listWIBResponseEndpoints)

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a List of Incident(s) of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(listWIBResponseEndpoints, indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

                if len(listWIBResponseEndpoints) < 1:

                    self.dictReqHandlerEnv["bWIBEndpointsFetchExhausted"] = True

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientEndpoints()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientHostnames(self, chostnamesoffset=0, chostnameslimit=0) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientHostnames()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        cHostnamesOffset = chostnamesoffset

        if cHostnamesOffset < 0:

            cHostnamesOffset = 0

        cHostnamesLimit = chostnameslimit

        if cHostnamesLimit > self.dictPy3GblEnv["cWIBHostnamesAPIMax"]:

            cHostnamesLimit = self.dictPy3GblEnv["cWIBHostnamesAPIMax"]

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            print("%s The URL Request 'cHostnamesOffset' is [%d] and 'cHostnamesLimit' is [%d]..." % (self.dictPy3GblEnv["sScriptDisp"], cHostnamesOffset, cHostnamesLimit))
            print("", flush=True)

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"                
        #
        #   "POST" Response 'Ok' (200): https://wib-product.wib-security.com/api/v2/inventory/hostnames/search?offset=0&limit=50
        #                                   -> {"sortBy":[{"key":"RISK_SCORE", "direction":"DESC"}]} 
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpPostRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "POST"
            wibReqURL      = ("https://%s/api/v2/inventory/hostnames/search?offset=%d&limit=%d" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], cHostnamesOffset, cHostnamesLimit))
            wibReqDataLoad = {"sortBy"          : [{"key"       : "RISK_SCORE",
                                                    "direction" : "DESC",
                                                   }
                                                  ]
                             }
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "Content-Type"    : "application/json",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with 'data' of [%s] and header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqDataLoad, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, json=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                    print("")
                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                self.dictReqHandlerEnv["wibReqResponseJson"] = wibReqResponseJson
            
                if type(wibReqResponseJson) != dict:
            
                    self.dictPy3GblEnv["bProcessingError"] = True
            
                    print("%s The URL Request returned a Response 'json' object of Type [%s] that is NOT the expected Dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson)))
                    print("", flush=True)
            
                    return
            
                dictWIBResponseHostnames = wibReqResponseJson
            
                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Dictionary of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(dictWIBResponseHostnames, indent=4))
                    print("", flush=True)

                listWIBResponseHostnames = []
            
                if "items" in dictWIBResponseHostnames:
             
                    listWIBResponseHostnames = dictWIBResponseHostnames["items"]
             
                    if listWIBResponseHostnames       == None or \
                       type(listWIBResponseHostnames) != list:
             
                        self.dictPy3GblEnv["bProcessingError"] = True
             
                        print("%s The URL Response dictionary key of 'items' (Hostnames(s)) has a value of None or is NOT of a List Type - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                        print("", flush=True)
             
                        return
             
                if "Hostnames" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:
             
                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Hostnames"]          = dictWIBResponseHostnames
                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Hostnames"]["items"] = []
             
                print("%s Extending the 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"][\"Hostnames\"][\"items\"]' List with (%d) item(s)..." % (self.dictPy3GblEnv["sScriptDisp"], len(listWIBResponseHostnames)))
                print("", flush=True)
             
                self.dictReqHandlerEnv["dictWIBPlatformData"]["Hostnames"]["items"].extend(listWIBResponseHostnames)

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a List of Incident(s) of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(listWIBResponseHostnames, indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

                if len(listWIBResponseHostnames) < 1:

                    self.dictReqHandlerEnv["bWIBHostnamesFetchExhausted"] = True

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientHostnames()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __retrieveHttpClientRepositories(self, crepositoriesoffset=0, crepositorieslimit=0) -> None:

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'self.dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        self.dictPy3GblEnv["bProcessingError"] = False

        if self.dictReqHandlerEnv["wibAccessTokenToken"] != None:

            self.dictReqHandlerEnv["wibAccessTokenToken"] = self.dictReqHandlerEnv["wibAccessTokenToken"].strip()

        if self.dictReqHandlerEnv["wibAccessTokenToken"] == None or \
           len(self.dictReqHandlerEnv["wibAccessTokenToken"]) < 1:

            self.dictPy3GblEnv["bProcessingError"] = True

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientRepositories()' - 'client' Session failed to obtain an OAuth2 'access' Token - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return

        cRepositoriesOffset = crepositoriesoffset

        if cRepositoriesOffset < 0:

            cRepositoriesOffset = 0

        cRepositoriesLimit = crepositorieslimit

        if cRepositoriesLimit > self.dictPy3GblEnv["cWIBRepositoriesAPIMax"]:

            cRepositoriesLimit = self.dictPy3GblEnv["cWIBRepositoriesAPIMax"]

        try:

            self.dictPy3GblEnv["bProcessingError"] = False

            print("%s The URL Request 'cRepositoriesOffset' is [%d] and 'cRepositoriesLimit' is [%d]..." % (self.dictPy3GblEnv["sScriptDisp"], cRepositoriesOffset, cRepositoriesLimit))
            print("", flush=True)

        # -------------------------------------------------------------------------------------------------------------
        #   dictPy3GblEnv["sWIBAccessTokenType"]    = "Bearer"
        #   dictPy3GblEnv["sWIBAccessToken"]        = ""
        #   dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"
        #   dictPy3GblEnv["sWIBPlatformServerPort"] = "443"                
        #
        #   "POST" Response 'Ok' (200): https://wib-product.wib-security.com/api/v2/inventory/repositories/search?offset=0&limit=50
        #                                   -> {"sortBy":[{"key":"RISK_SCORE", "direction":"DESC"}]} 
        #
        # -------------------------------------------------------------------------------------------------------------

            self.dictPy3GblEnv["cHttpPostRequests"] += 1

            wibReqRespOk   = [200]
            wibReqType     = "POST"
            wibReqURL      = ("https://%s/api/v2/inventory/repositories/search?offset=%d&limit=%d" % (self.dictPy3GblEnv["sWIBPlatformServerHost"], cRepositoriesOffset, cRepositoriesLimit))
            wibReqDataLoad = {"sortBy"          : [{"key"       : "RISK_SCORE",
                                                    "direction" : "DESC",
                                                   }
                                                  ]
                             }
            wibReqHeaders  = {"Accept"          : "*/*",
                              "Accept-Encoding" : "gzip, deflate, br",
                              "Accept-Language" : "en-US,en;q=0.5",
                              "Content-Type"    : "application/json",
                              "cache-control"   : "no-cache",
                              "Authorization"   : ("Bearer %s"        % (self.dictReqHandlerEnv["wibAccessTokenToken"])),
                              "originURL"       : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "documentURL"     : ("https://%s/"      % (self.dictPy3GblEnv["sWIBPlatformServerHost"])),
                              "User-Agent"      : "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0",
                             }

            print("%s Issuing a '%s' to URL [%s] with 'data' of [%s] and header(s) of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqType, wibReqURL, wibReqDataLoad, wibReqHeaders), flush=True)

            async with self.dictReqHandlerEnv["wibAioHttpSession"].request(wibReqType, wibReqURL, json=wibReqDataLoad, headers=wibReqHeaders) as wibReqResponse:

                if wibReqResponse == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'wibReqResponse' object that is 'None' - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                print("%s The URL Request returned a 'status' code of [%s] and Type of [%s] with a 'wibReqResponse' object Type of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), type(wibReqResponse)))
                print("")

                if wibReqResponse.status in wibReqRespOk:

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is a 'good' response..." % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status)))

                else:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a 'status' code of [%s] Type [%s] is NOT a 'good' response of [%s] - Error!" % (self.dictPy3GblEnv["sScriptDisp"], wibReqResponse.status, type(wibReqResponse.status), wibReqRespOk))
                    print("")
                    print("%s The URL Request returned Response text of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], await wibReqResponse.text()))
                    print("")

                if self.dictPy3GblEnv["bProcessingError"] == True:

                    return

                wibReqResponseJson = await wibReqResponse.json()

                if wibReqResponseJson == None:

                    self.dictPy3GblEnv["bProcessingError"] = True

                    print("%s The URL Request returned a Response 'json' object that is None - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("", flush=True)

                    return

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Response 'json' object of Type [%s] and a value of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson), wibReqResponseJson))
                    print("")
                    print("%s Response 'json' PRETTY Print (Initial Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print(json.dumps(wibReqResponseJson, indent=4))
                    print("", flush=True)

                self.dictReqHandlerEnv["wibReqResponseJson"] = wibReqResponseJson
            
                if type(wibReqResponseJson) != dict:
            
                    self.dictPy3GblEnv["bProcessingError"] = True
            
                    print("%s The URL Request returned a Response 'json' object of Type [%s] that is NOT the expected Dictionary - Error!" % (self.dictPy3GblEnv["sScriptDisp"], type(wibReqResponseJson)))
                    print("", flush=True)
            
                    return
            
                dictWIBResponseRepositories = wibReqResponseJson
            
                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a Dictionary of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(dictWIBResponseRepositories, indent=4))
                    print("", flush=True)

                listWIBResponseRepositories = []
            
                if "items" in dictWIBResponseRepositories:
             
                    listWIBResponseRepositories = dictWIBResponseRepositories["items"]
             
                    if listWIBResponseRepositories       == None or \
                       type(listWIBResponseRepositories) != list:
             
                        self.dictPy3GblEnv["bProcessingError"] = True
             
                        print("%s The URL Response dictionary key of 'items' (Repositories(s)) has a value of None or is NOT of a List Type - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))
                        print("", flush=True)
             
                        return
             
                if "Repositories" not in self.dictReqHandlerEnv["dictWIBPlatformData"]:
             
                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Repositories"]          = dictWIBResponseRepositories
                    self.dictReqHandlerEnv["dictWIBPlatformData"]["Repositories"]["items"] = []
             
                print("%s Extending the 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"][\"Repositories\"][\"items\"]' List with (%d) item(s)..." % (self.dictPy3GblEnv["sScriptDisp"], len(listWIBResponseRepositories)))
                print("", flush=True)
             
                self.dictReqHandlerEnv["dictWIBPlatformData"]["Repositories"]["items"].extend(listWIBResponseRepositories)

                if self.dictPy3GblEnv["bVerbose"] == True:

                    print("%s The URL Request returned a List of Incident(s) of (Processed Dump):" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("")
                    print(json.dumps(listWIBResponseRepositories, indent=4))
                    print("", flush=True)

                    print("%s The URL Request returned Response 'dictionaries' of:" % (self.dictPy3GblEnv["sScriptDisp"]))
                    print("    'cookies'     of [%s]...:" % (wibReqResponse.cookies))
                    print("    'headers'     of [%s]...:" % (str(wibReqResponse.headers)))
                    print("    'raw_headers' of [%s]...:" % (str(wibReqResponse.raw_headers)))
                    print("", flush=True)

                if len(listWIBResponseRepositories) < 1:

                    self.dictReqHandlerEnv["bWIBRepositoriesFetchExhausted"] = True

        except Exception as inst:

            print("%s 'HttpRequestHandlerClient.__retrieveHttpClientRepositories()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return

    async def __outputWIBPlatformData(self):
 
        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "AioHttp 'Request' Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        if dictPy3GblEnv["sScriptOutputWIBPlatformFile"] != None:

            dictPy3GblEnv["sScriptOutputWIBPlatformFile"] = dictPy3GblEnv["sScriptOutputWIBPlatformFile"].strip()

        if dictPy3GblEnv["sScriptOutputWIBPlatformFile"] == None or \
           len(dictPy3GblEnv["sScriptOutputWIBPlatformFile"]) < 1:

            print("%s The (Output) WIB Platform data filename is None or Empty - this is required for output - Skipping the output of data - Warning!" % (self.dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            dictPy3GblEnv["sScriptOutputWIBPlatformFile"] = None

            return True

        try:
 
            print("")
            print("======================== WIB Platform Data OUTPUT ===========================")

            if len(self.dictReqHandlerEnv["dictWIBPlatformData"]) < 1:

                print("%s Dictionary 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"]' contains NO Items - Error!" % (self.dictPy3GblEnv["sScriptDisp"]))

                self.dictPy3GblEnv["bProcessingError"] = True

                return False

            print("%s '__outputWIBPlatformData()' - Command is generating the (Output) WIB Platform data file of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sScriptOutputWIBPlatformFile"]))
            print("")

            fOutputWIBIncidents = open(dictPy3GblEnv["sScriptOutputWIBPlatformFile"], "w")

            fOutputWIBIncidents.write(json.dumps(self.dictReqHandlerEnv["dictWIBPlatformData"], indent=4, sort_keys=False, default=json_util.default))
            fOutputWIBIncidents.close()

            print("%s '__outputWIBPlatformData()' - Command is generated the (Output) WIB Platform data file of [%s]..." % (self.dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sScriptOutputWIBPlatformFile"]))
            print("")
            print("=============================================================================")
            print("", flush=True)
 
        except Exception as inst:
 
            print("%s '__outputWIBPlatformData()' - exception occured..." % (self.dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)
 
            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)
 
            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)
 
            self.dictPy3GblEnv["bProcessingError"] = True
 
            return False
 
        return True

# - - - - - - -
# 'main' method:
# - - - - - - -

def main():

    global dictPy3GblEnv

    # - - - - - TEST - - - - -
    #   dictPy3GblEnv = {}

    assert len(dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'dictPy3GblEnv' has NO Element(s) - Fatal!"

    try:

        dtNow       = datetime.now()
        sDTNowStamp = dtNow.strftime("%Y/%m/%d at %H:%M:%S")

        print("%s The WIB Platform RestAPI data Fetch (asyncio) #3 by Python is starting execution from Server [%s] on [%s] under Python [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sServerNode"], sDTNowStamp, dictPy3GblEnv["sPythonVers"]))
        print("")

        if dictPy3GblEnv["bPlatformIsWindows"] == True:

            import win32con
            import win32api

            print("%s The platform 'system' of [%s] indicates this is a Microsoft/Windows system - 'win32con'/'win32api' have been imported..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sPlatform"]))

        else:

            print("%s The platform 'system' is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sPlatform"]))

        # Handle the parameter(s) processing...

        dictPy3GblEnv["optParser"].add_option("-v", "--verbose", dest="run_verbose", default=False, help="Run VERBOSE", action="store_true")
        dictPy3GblEnv["optParser"].add_option("-o", "--output-wib-platform-file", dest="output_wib_platform_file", default="", help="(Output) WIB Platform data file", metavar="Output-WIB-Platform-file")

    #   dictPy3GblEnv["optParser"].add_option("--wib-host", dest="wib_server_host", default="wib-product.wib-security.com", help="WIB Platform Server 'host'", metavar="WIBPlatform-Server-Host")
        dictPy3GblEnv["optParser"].add_option("--wib-host", dest="wib_server_host", default="demo.wib-security.com", help="WIB Platform Server 'host'", metavar="WIBPlatform-Server-Host")
        dictPy3GblEnv["optParser"].add_option("--wib-port", dest="wib_server_port", default="443", help="WIB Platform Server 'port'", metavar="WIBPlatform-Server-Port")
        dictPy3GblEnv["optParser"].add_option("--user", dest="wib_username", default="daryl.cox@wib.com", help="WIB Portal 'username'", metavar="WIB-Portal-Username")
        dictPy3GblEnv["optParser"].add_option("--pswd", dest="wib_password", default="C0rky9#M4r#2023", help="WIB Portal 'password'", metavar="WIB-Portal-Password")

        dictPy3GblEnv["optParser"].add_option("--stats-days", dest="wib_stats_days", default="7", help="WIB Platform 'statistics' Days (range)")

        dictPy3GblEnv["optParser"].add_option("--incidents-severity", dest="wib_incidents_severity", default="CRITICAL", help="WIB Platform 'incident(s)' Severity - semicolon separated: [CRITICAL;HIGH;MEDIUM;LOW] -or- [ALL]")
        dictPy3GblEnv["optParser"].add_option("--incidents-days", dest="wib_incidents_days", default="30", help="WIB Platform 'incident(s)' Days (range)")
        dictPy3GblEnv["optParser"].add_option("--incidents-limit", dest="wib_incidents_limit", default="50", help="WIB Platform 'incident(s)' Limit (count)")
        dictPy3GblEnv["optParser"].add_option("--vulnerabilities-days", dest="wib_vulnerabilities_days", default="30", help="WIB Platform 'vulnerabilities' Days (range)")
        dictPy3GblEnv["optParser"].add_option("--vulnerabilities-limit", dest="wib_vulnerabilities_limit", default="50", help="WIB Platform 'vulnerabilities' Limit (count)")
        dictPy3GblEnv["optParser"].add_option("--misconfigurations-days", dest="wib_misconfigurations_days", default="30", help="WIB Platform 'misconfigurations' Days (range)")
        dictPy3GblEnv["optParser"].add_option("--misconfigurations-limit", dest="wib_misconfigurations_limit", default="50", help="WIB Platform 'misconfigurations' Limit (count)")

        dictPy3GblEnv["optParser"].add_option("--endpoints-limit", dest="wib_endpoints_limit", default="50000", help="WIB Platform 'endpoint(s)' Limit (count)")
        dictPy3GblEnv["optParser"].add_option("--hostnames-limit", dest="wib_hostnames_limit", default="5000", help="WIB Platform 'hostname(s)' Limit (count)")
        dictPy3GblEnv["optParser"].add_option("--repositories-limit", dest="wib_repositories_limit", default="500", help="WIB Platform 'repositories' Limit (count)")

        dictPy3GblEnv["optParser"].add_option("--token-type", dest="access_token_type", default="Bearer", help="(OAuth2) 'implicit' Access 'token' TYPE")
        dictPy3GblEnv["optParser"].add_option("--token", dest="access_token", default="", help="(OAuth2) 'implicit' Access 'token'")

        (options, args) = dictPy3GblEnv["optParser"].parse_args()

        dictPy3GblEnv["bVerbose"]                     = options.run_verbose
        dictPy3GblEnv["sScriptOutputWIBPlatformFile"] = options.output_wib_platform_file.strip()

        dictPy3GblEnv["sWIBPlatformServerHost"]       = options.wib_server_host.strip()
        dictPy3GblEnv["sWIBPlatformServerPort"]       = options.wib_server_port.strip()
        dictPy3GblEnv["sWIBPlatformUsername"]         = options.wib_username.strip()
        dictPy3GblEnv["sWIBPlatformPassword"]         = options.wib_password.strip()

        dictPy3GblEnv["sWIBStatisticsDays"]           = options.wib_stats_days.strip()

        dictPy3GblEnv["sWIBIncidentsSeverity"]        = options.wib_incidents_severity.strip()
        dictPy3GblEnv["sWIBIncidentsDays"]            = options.wib_incidents_days.strip()
        dictPy3GblEnv["sWIBIncidentsLimit"]           = options.wib_incidents_limit.strip()
        dictPy3GblEnv["sWIBVulnerabilitiesDays"]      = options.wib_vulnerabilities_days.strip()
        dictPy3GblEnv["sWIBVulnerabilitiesLimit"]     = options.wib_vulnerabilities_limit.strip()
        dictPy3GblEnv["sWIBMisconfigurationsDays"]    = options.wib_misconfigurations_days.strip()
        dictPy3GblEnv["sWIBMisconfigurationsLimit"]   = options.wib_misconfigurations_limit.strip()

        dictPy3GblEnv["sWIBEndpointsLimit"]           = options.wib_endpoints_limit.strip()
        dictPy3GblEnv["sWIBHostnamesLimit"]           = options.wib_hostnames_limit.strip()
        dictPy3GblEnv["sWIBRepositoriesLimit"]        = options.wib_repositories_limit.strip()

        dictPy3GblEnv["sWIBAccessTokenType"]          = options.access_token_type.strip()
        dictPy3GblEnv["sWIBAccessToken"]              = options.access_token.strip()

        if dictPy3GblEnv["sWIBPlatformServerHost"] != None:

            dictPy3GblEnv["sWIBPlatformServerHost"] = dictPy3GblEnv["sWIBPlatformServerHost"].strip()

        if dictPy3GblEnv["sWIBPlatformServerHost"] == None or \
           len(dictPy3GblEnv["sWIBPlatformServerHost"]) < 1:

            dictPy3GblEnv["sWIBPlatformServerHost"] = "wib-product.wib-security.com"

        if dictPy3GblEnv["sWIBPlatformServerPort"] != None:

            dictPy3GblEnv["sWIBPlatformServerPort"] = dictPy3GblEnv["sWIBPlatformServerPort"].strip()

        if dictPy3GblEnv["sWIBPlatformServerPort"] == None or \
           len(dictPy3GblEnv["sWIBPlatformServerPort"]) < 1:

            dictPy3GblEnv["sWIBPlatformServerPort"] = "443"

        dictPy3GblEnv["iWIBPlatformServerPort"] = int(dictPy3GblEnv["sWIBPlatformServerPort"])

        if dictPy3GblEnv["sWIBPlatformUsername"] != None:

            dictPy3GblEnv["sWIBPlatformUsername"] = dictPy3GblEnv["sWIBPlatformUsername"].strip()

        if dictPy3GblEnv["sWIBPlatformUsername"] == None or \
           len(dictPy3GblEnv["sWIBPlatformUsername"]) < 1:

            dictPy3GblEnv["sWIBPlatformUsername"] = "daryl.cox@wib.com"

        if dictPy3GblEnv["sWIBPlatformPassword"] != None:

            dictPy3GblEnv["sWIBPlatformPassword"] = dictPy3GblEnv["sWIBPlatformPassword"].strip()

        if dictPy3GblEnv["sWIBPlatformPassword"] == None or \
           len(dictPy3GblEnv["sWIBPlatformPassword"]) < 1:

            dictPy3GblEnv["sWIBPlatformPassword"] = "C0rky9#M4r#2023"

        if dictPy3GblEnv["sWIBStatisticsDays"] != None:

            dictPy3GblEnv["sWIBStatisticsDays"] = dictPy3GblEnv["sWIBStatisticsDays"].strip()

        if dictPy3GblEnv["sWIBStatisticsDays"] == None or \
           len(dictPy3GblEnv["sWIBStatisticsDays"]) < 1:

            dictPy3GblEnv["sWIBStatisticsDays"] = "7"

        if dictPy3GblEnv["sWIBIncidentsSeverity"] != None:

            dictPy3GblEnv["sWIBIncidentsSeverity"] = dictPy3GblEnv["sWIBIncidentsSeverity"].strip()

        if dictPy3GblEnv["sWIBIncidentsSeverity"] == None or \
           len(dictPy3GblEnv["sWIBIncidentsSeverity"]) < 1:

            dictPy3GblEnv["sWIBIncidentsSeverity"]    = "CRITICAL"
            dictPy3GblEnv["listWIBIncidentsSeverity"] = [dictPy3GblEnv["sWIBIncidentsSeverity"]]

        else:

            # (Filter) WIB Incident(s) 'severity' processing...

            dictPy3GblEnv["listWIBIncidentsSeverity"] = []
            asWIBIncidentsSeverities                  = []

            if dictPy3GblEnv["bVerbose"] == True:

                print("%s Command received a WIB Incident(s) 'severities' string of [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBIncidentsSeverity"]))

            dictPy3GblEnv["sWIBIncidentsSeverityUpper"] = dictPy3GblEnv["sWIBIncidentsSeverity"].upper()

            if dictPy3GblEnv["sWIBIncidentsSeverityUpper"].find(';') < 0:

                if dictPy3GblEnv["sWIBIncidentsSeverityUpper"] == "[ALL]":

                    asWIBIncidentsSeverities.append("CRITICAL")
                    asWIBIncidentsSeverities.append("HIGH")
                    asWIBIncidentsSeverities.append("MEDIUM")
                    asWIBIncidentsSeverities.append("LOW")

                    if dictPy3GblEnv["bVerbose"] == True:

                        print("%s Command received a WIB Incident(s) 'severities' string of '[all]' - ALL individual 'severities' will be used..." % (dictPy3GblEnv["sScriptDisp"]))

                else:

                    asWIBIncidentsSeverities.append(dictPy3GblEnv["sWIBIncidentsSeverityUpper"])

                    if dictPy3GblEnv["bVerbose"] == True:

                        print("%s Command received a WIB Incident(s) 'severities' string of [%s] - that individual 'severity' will be used..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBIncidentsSeverityUpper"]))

            else:

                asWIBIncidentsSeverities = dictPy3GblEnv["sWIBIncidentsSeverityUpper"].split(';')

            dictPy3GblEnv["listWIBIncidentsSeverity"] = asWIBIncidentsSeverities

            print("%s The WIB Incident(s) 'severities' list is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["listWIBIncidentsSeverity"]))

        dictPy3GblEnv["sWIBVulnerabilitiesSeverity"]      = dictPy3GblEnv["sWIBIncidentsSeverity"]
        dictPy3GblEnv["listWIBVulnerabilitiesSeverity"]   = dictPy3GblEnv["listWIBIncidentsSeverity"]

        dictPy3GblEnv["sWIBMisconfigurationsSeverity"]    = dictPy3GblEnv["sWIBIncidentsSeverity"]
        dictPy3GblEnv["listWIBMisconfigurationsSeverity"] = dictPy3GblEnv["listWIBIncidentsSeverity"]

        if dictPy3GblEnv["sWIBIncidentsDays"] != None:

            dictPy3GblEnv["sWIBIncidentsDays"] = dictPy3GblEnv["sWIBIncidentsDays"].strip()

        if dictPy3GblEnv["sWIBIncidentsDays"] == None or \
           len(dictPy3GblEnv["sWIBIncidentsDays"]) < 1:

            dictPy3GblEnv["sWIBIncidentsDays"] = "30"

        if dictPy3GblEnv["sWIBIncidentsLimit"] != None:

            dictPy3GblEnv["sWIBIncidentsLimit"] = dictPy3GblEnv["sWIBIncidentsLimit"].strip()

        if dictPy3GblEnv["sWIBIncidentsLimit"] == None or \
           len(dictPy3GblEnv["sWIBIncidentsLimit"]) < 1:

            dictPy3GblEnv["sWIBIncidentsLimit"] = "50"

        if dictPy3GblEnv["sWIBVulnerabilitiesDays"] != None:

            dictPy3GblEnv["sWIBVulnerabilitiesDays"] = dictPy3GblEnv["sWIBVulnerabilitiesDays"].strip()

        if dictPy3GblEnv["sWIBVulnerabilitiesDays"] == None or \
           len(dictPy3GblEnv["sWIBVulnerabilitiesDays"]) < 1:

            dictPy3GblEnv["sWIBVulnerabilitiesDays"] = "30"

        if dictPy3GblEnv["sWIBVulnerabilitiesLimit"] != None:

            dictPy3GblEnv["sWIBVulnerabilitiesLimit"] = dictPy3GblEnv["sWIBVulnerabilitiesLimit"].strip()

        if dictPy3GblEnv["sWIBVulnerabilitiesLimit"] == None or \
           len(dictPy3GblEnv["sWIBVulnerabilitiesLimit"]) < 1:

            dictPy3GblEnv["sWIBVulnerabilitiesLimit"] = "50"

        if dictPy3GblEnv["sWIBMisconfigurationsDays"] != None:

            dictPy3GblEnv["sWIBMisconfigurationsDays"] = dictPy3GblEnv["sWIBMisconfigurationsDays"].strip()

        if dictPy3GblEnv["sWIBMisconfigurationsDays"] == None or \
           len(dictPy3GblEnv["sWIBMisconfigurationsDays"]) < 1:

            dictPy3GblEnv["sWIBMisconfigurationsDays"] = "30"

        if dictPy3GblEnv["sWIBMisconfigurationsLimit"] != None:

            dictPy3GblEnv["sWIBMisconfigurationsLimit"] = dictPy3GblEnv["sWIBMisconfigurationsLimit"].strip()

        if dictPy3GblEnv["sWIBMisconfigurationsLimit"] == None or \
           len(dictPy3GblEnv["sWIBMisconfigurationsLimit"]) < 1:

            dictPy3GblEnv["sWIBMisconfigurationsLimit"] = "20"

        if dictPy3GblEnv["sWIBEndpointsLimit"] != None:

            dictPy3GblEnv["sWIBEndpointsLimit"] = dictPy3GblEnv["sWIBEndpointsLimit"].strip()

        if dictPy3GblEnv["sWIBEndpointsLimit"] == None or \
           len(dictPy3GblEnv["sWIBEndpointsLimit"]) < 1:

            dictPy3GblEnv["sWIBEndpointsLimit"] = "50000"

        if dictPy3GblEnv["sWIBHostnamesLimit"] != None:

            dictPy3GblEnv["sWIBHostnamesLimit"] = dictPy3GblEnv["sWIBHostnamesLimit"].strip()

        if dictPy3GblEnv["sWIBHostnamesLimit"] == None or \
           len(dictPy3GblEnv["sWIBHostnamesLimit"]) < 1:

            dictPy3GblEnv["sWIBHostnamesLimit"] = "5000"

        if dictPy3GblEnv["sWIBRepositoriesLimit"] != None:

            dictPy3GblEnv["sWIBRepositoriesLimit"] = dictPy3GblEnv["sWIBRepositoriesLimit"].strip()

        if dictPy3GblEnv["sWIBRepositoriesLimit"] == None or \
           len(dictPy3GblEnv["sWIBRepositoriesLimit"]) < 1:

            dictPy3GblEnv["sWIBRepositoriesLimit"] = "500"

        dictPy3GblEnv["sWIBStatisticsStartDate"]        = (dictPy3GblEnv["dtStartTime"] - timedelta(days=int(dictPy3GblEnv["sWIBStatisticsDays"]))).strftime("%Y-%m-%d")
        dictPy3GblEnv["sWIBIncidentsStartTime"]         = (dictPy3GblEnv["dtStartTime"] - timedelta(days=int(dictPy3GblEnv["sWIBIncidentsDays"]))).isoformat(sep='T', timespec='milliseconds')+"Z"
        dictPy3GblEnv["sWIBVulnerabilitiesStartTime"]   = (dictPy3GblEnv["dtStartTime"] - timedelta(days=int(dictPy3GblEnv["sWIBVulnerabilitiesDays"]))).isoformat(sep='T', timespec='milliseconds')+"Z"
        dictPy3GblEnv["sWIBMisconfigurationsStartTime"] = (dictPy3GblEnv["dtStartTime"] - timedelta(days=int(dictPy3GblEnv["sWIBMisconfigurationsDays"]))).isoformat(sep='T', timespec='milliseconds')+"Z"

        if dictPy3GblEnv["sWIBAccessTokenType"] != None:

            dictPy3GblEnv["sWIBAccessTokenType"] = dictPy3GblEnv["sWIBAccessTokenType"].strip()

        if dictPy3GblEnv["sWIBAccessTokenType"] == None or \
           len(dictPy3GblEnv["sWIBAccessTokenType"]) < 1:

            dictPy3GblEnv["sWIBAccessTokenType"] = "Bearer"

        if dictPy3GblEnv["sWIBAccessToken"] != None:

            dictPy3GblEnv["sWIBAccessToken"] = dictPy3GblEnv["sWIBAccessToken"].strip()

        if dictPy3GblEnv["sWIBAccessToken"] == None or \
           len(dictPy3GblEnv["sWIBAccessToken"]) < 1:

            dictPy3GblEnv["sWIBAccessToken"] = ""

    #   if dictPy3GblEnv["bVerbose"] == True:

        print("%s Command VERBOSE flag is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["bVerbose"]))
        print("%s Command (Output) WIB Platform data file is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sScriptOutputWIBPlatformFile"]))
        print("%s Command 'dictPy3GblEnv' is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv))
        print("")
        print("%s Command WIB Platform Server host       (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBPlatformServerHost"]))
        print("%s Command WIB Platform Server port       (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBPlatformServerPort"]))
        print("%s Command WIB Platform Server port          (int) is (%d)..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["iWIBPlatformServerPort"]))
        print("%s Command WIB Platform Username          (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBPlatformUsername"]))
        print("%s Command WIB Platform Password          (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBPlatformPassword"]))
        print("")
        print("%s Command WIB Statistics  'days'         (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBStatisticsDays"]))
        print("")
        print("%s Command WIB Incident(s) Severity       (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBIncidentsSeverity"]))
        print("%s Command WIB Incident(s) Severities       (list) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["listWIBIncidentsSeverity"]))
        print("%s Command WIB Vulnerabilities Severity   (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBVulnerabilitiesSeverity"]))
        print("%s Command WIB Vulnerabilities Severities   (list) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["listWIBVulnerabilitiesSeverity"]))
        print("%s Command WIB Misconfigurations Severity (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBMisconfigurationsSeverity"]))
        print("%s Command WIB Misconfigurations Severities (list) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["listWIBMisconfigurationsSeverity"]))
        print("")
        print("%s Command WIB Incident(s) 'days'         (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBIncidentsDays"]))
        print("%s Command WIB Incident(s) Limit          (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBIncidentsLimit"]))
        print("%s Command WIB Incident(s) API Max           (int) is [%d]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["cWIBIncidentsAPIMax"]))
        print("%s Command WIB Vulnerabilities 'days'     (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBVulnerabilitiesDays"]))
        print("%s Command WIB Vulnerabilities Limit      (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBVulnerabilitiesLimit"]))
        print("%s Command WIB Vulnerabilities API Max       (int) is [%d]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["cWIBVulnerabilitiesAPIMax"]))
        print("%s Command WIB Misconfigurations 'days'   (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBMisconfigurationsDays"]))
        print("%s Command WIB Misconfigurations Limit    (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBMisconfigurationsLimit"]))
        print("%s Command WIB Misconfigurations API Max     (int) is [%d]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["cWIBMisconfigurationsAPIMax"]))
        print("")
        print("%s Command WIB Endpoint(s) Limit          (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBEndpointsLimit"]))
        print("%s Command WIB Endpoint(s) API Max           (int) is [%d]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["cWIBEndpointsAPIMax"]))
        print("%s Command WIB Hostname(s) Limit          (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBHostnamesLimit"]))
        print("%s Command WIB Hostname(s) API Max           (int) is [%d]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["cWIBHostnamesAPIMax"]))
        print("%s Command WIB Repositories Limit         (string) is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBRepositoriesLimit"]))
        print("%s Command WIB Repositories API Max          (int) is [%d]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["cWIBRepositoriesAPIMax"]))
        print("")
        print("%s Command WIB Platform Access 'token' TYPE        is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBAccessTokenType"]))
        print("%s Command WIB Platform Access 'token'             is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sWIBAccessToken"]))
        print("", flush=True)

        if dictPy3GblEnv["sScriptOutputWIBPlatformFile"] != None:

            dictPy3GblEnv["sScriptOutputWIBPlatformFile"] = dictPy3GblEnv["sScriptOutputWIBPlatformFile"].strip()

        if dictPy3GblEnv["sScriptOutputWIBPlatformFile"] == None or \
           len(dictPy3GblEnv["sScriptOutputWIBPlatformFile"]) < 1:

            print("%s The (Output) WIB Platform data filename is None or Empty - this is required for output - Skipping the output of data - Warning!" % (dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            dictPy3GblEnv["sScriptOutputWIBPlatformFile"] = None

    #   Main 'processing'...

        try:

            httpReqHandler = HttpRequestHandlerClient(dictPy3GblEnv)
            asyncioLoop    = asyncio.new_event_loop()

            asyncioLoop.run_until_complete(httpReqHandler.retrieveWIBPortalData())

            asyncioLoop.close()

        except Exception as inst:

            print("%s 'main()' - 'main()' - exception occured..." % (dictPy3GblEnv["sScriptDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            dictPy3GblEnv["bProcessingError"] = True

        except KeyboardInterrupt:

            print("%s 'main()' - KeyboardInterrupt - Web Server is Shutting down..." % (dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

    #   Cleanup...

        print("")        
        print("%s The WIB Platform RestAPI data Fetch used (%d) 'GET' request(s) and (%d) 'POST' request(s) - TOTAL request(s) (%d)..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["cHttpGetRequests"], dictPy3GblEnv["cHttpPostRequests"], (dictPy3GblEnv["cHttpGetRequests"] + dictPy3GblEnv["cHttpPostRequests"])))
        print("", flush=True)

        dtNow       = datetime.now()
        sDTNowStamp = dtNow.strftime("%Y/%m/%d at %H:%M:%S")

        print("%s The WIB Platform RestAPI data Fetch (asyncio) #3 by Python is ending execution from Server [%s] on [%s] under Python [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sServerNode"], sDTNowStamp, dictPy3GblEnv["sPythonVers"]))
        print("", flush=True)

    except Exception as inst:

        print("%s 'main()' - exception occured..." % (dictPy3GblEnv["sScriptDisp"]))
        print(type(inst))
        print(inst)

        excType, excValue, excTraceback = sys.exc_info()
        asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

        print("- - - ")
        print('\n'.join(asTracebackLines))
        print("- - - ", flush=True)

        dictPy3GblEnv["bProcessingError"] = True

        return False

    return True

# - - - - - - -
# 'main' logic:
# - - - - - - -

if __name__ == '__main__':

    try:

        pass

    except Exception as inst:

        print("%s '<before>-main()' - exception occured..." % (dictPy3GblEnv["sScriptDisp"]))
        print(type(inst))
        print(inst)

        excType, excValue, excTraceback = sys.exc_info()
        asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

        print("- - - ")
        print('\n'.join(asTracebackLines))
        print("- - - ")

        sys.exit(99)

    bCmdExecOk  = main()

    dtNow       = datetime.now()
    sDTNowStamp = dtNow.strftime("%Y/%m/%d at %H:%M:%S")
    tmEndTime   = time.time()
    tmElapsed   = (tmEndTime - dictPy3GblEnv["tmStartTime"])
    sTMElapsed  = time.strftime("%H:%M:%S", time.gmtime(tmElapsed))

    print("%s The Platform RestAPI data Fetch (asyncio) #3 by Python is ending execution with an 'elapsed' time of [%s - (%f)]..." % (dictPy3GblEnv["sScriptDisp"], sTMElapsed, tmElapsed))
    print("", flush=True)

    if bCmdExecOk                        == False or \
       dictPy3GblEnv["bProcessingError"] == True:

        print("%s Exiting with a Return Code of (31)..." % (dictPy3GblEnv["sScriptDisp"]))
        print("", flush=True)

        sys.exit(31)

    print("%s Exiting with a Return Code of (0)..." % (dictPy3GblEnv["sScriptDisp"]))
    print("", flush=True)

    sys.exit(0)

