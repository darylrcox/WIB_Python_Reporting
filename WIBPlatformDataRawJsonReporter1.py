
#!/usr/bin/python3.10

# --------------------------------------------------------------------------------------------------------------
# Notes:
#
#   This module is written to read and report data directly output from the WIB Platform 
#   RestAPI 'strict JSON' Fetch #1. PDF output is built from the JSON using 'json.dumps()'.
# --------------------------------------------------------------------------------------------------------------

import optparse
import os
import traceback
import platform
import re
import string
import sys
import collections
import statistics
import time
import json
# import pymongo

from datetime import datetime
from bson     import json_util
# from pymongo  import ISODate

from reportlab.lib.pagesizes import LETTER  
from reportlab.lib.units     import inch  
from reportlab.pdfgen.canvas import Canvas  
from reportlab.lib.colors    import black
from reportlab.lib.colors    import purple  
from reportlab.lib.colors    import darkgreen 
from reportlab.lib.colors    import darkcyan

dictPy3GblEnv = collections.defaultdict()

# - - - - - Setup the Python3 'Global' Environment dictionary (standard) - - - - -

dictPy3GblEnv["bVerbose"]           = False
dictPy3GblEnv["bProcessingError"]   = False
dictPy3GblEnv["optParser"]          = optparse.OptionParser()
dictPy3GblEnv["sScriptId"]          = dictPy3GblEnv["optParser"].get_prog_name()
dictPy3GblEnv["sScriptVers"]        = "(v1.0107)"
dictPy3GblEnv["sScriptDisp"]        = ("%s %s:" % (dictPy3GblEnv["sScriptId"], dictPy3GblEnv["sScriptVers"]))
dictPy3GblEnv["cScriptArgc"]        = len(sys.argv)

# - - - - - Setup the Python3 'Global' Environment dictionary (extended) - - - - -

dictPy3GblEnv["tmStartTime"]        = time.time()
dictPy3GblEnv["sCurrentWorkingDir"] = os.getcwd()
dictPy3GblEnv["sPythonVers"]        = ("v%s.%s.%s" % (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)) 
dictPy3GblEnv["sServerNode"]        = platform.node()
dictPy3GblEnv["sPlatform"]          = platform.system()
dictPy3GblEnv["sPlatformPathSep"]   = None
dictPy3GblEnv["bPlatformIsWindows"] = dictPy3GblEnv["sPlatform"].startswith('Windows')

if dictPy3GblEnv["bPlatformIsWindows"] == False:

    dictPy3GblEnv["bPlatformIsWindows"] = dictPy3GblEnv["sPlatform"].startswith('Microsoft')

if dictPy3GblEnv["bPlatformIsWindows"] == True:

    dictPy3GblEnv["sPlatformPathSep"]   = "\\"

else:

    dictPy3GblEnv["sPlatformPathSep"]   = "/"

# Parameter and Application 'global' item(s):

dictPy3GblEnv["sScriptInputWIBPlatformDataFile"]    = ""
dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"]  = ""

# List of WIB Platform 'keys' in the order to 'report' on:

dictPy3GblEnv["asScriptWIBPlatformDataReportOrder"] = ["StatisticsAggregated",
                                                       "StatisticsDaily",
                                                       "Incidents"]

# Class to handle the WIB Json scanning...

class HandleWIBPlatformRawJsonReporting(object):

    sClassMod         = __name__
    sClassId          = "HandleWIBPlatformRawJsonReporting"
    sClassVers        = "(v0.0000)"
    sClassDisp        = sClassMod+"."+sClassId+" "+sClassVers+": "

    dictPy3GblEnv     = None
    dictReqHandlerEnv = None

    def __init__(self, dictpy3gblenv=None):

        try:

            self.setPy3GblEnv(dictpy3gblenv=dictpy3gblenv)

            if self.sClassMod == "__main__":

                self.sClassMod = "<<<Class>>>"

            self.sClassVers = self.dictPy3GblEnv["sScriptVers"]
            self.sClassDisp = self.sClassMod+"."+self.sClassId+" "+self.sClassVers+": "

            self.dictReqHandlerEnv = collections.defaultdict()

            # - - - - - Setup the WIB Handler Environment dictionary (standard) - - - - -

            self.dictReqHandlerEnv["sClassId"]   = self.sClassId
            self.dictReqHandlerEnv["sClassVers"] = self.sClassVers
            self.dictReqHandlerEnv["sClassDisp"] = self.sClassDisp

        except Exception as inst:

            print("%s '__init__()' - exception occured..." % (self.sClassDisp))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

    def getPy3GblEnv(self):

        return self.dictPy3GblEnv

    def setPy3GblEnv(self, dictpy3gblenv=None):

        self.dictPy3GblEnv = dictpy3gblenv

    def getWIBHandlerEnv(self):

        return self.dictReqHandlerEnv

    def setWIBHandlerEnv(self, dictReqHandlerEnv=None):

        self.dictReqHandlerEnv = dictReqHandlerEnv

    def dump_fields(self):

        if self.dictPy3GblEnv["bVerbose"] == True:

            print("%s Dump of the variable(s) content of this class:" % (self.sClassDisp))
            print("%s The contents of 'dictPy3GblEnv' is [%s]..." % (self.sClassDisp, self.dictPy3GblEnv))
            print("%s The contents of 'dictReqHandlerEnv' is [%s]..." % (self.sClassDisp, self.dictReqHandlerEnv))

    def toString(self):

        asObjDetail = list()

        asObjDetail.append("'sClassDisp' is [%s], " % (self.sClassDisp))
        asObjDetail.append("'dictPy3GblEnv' is [%s], " % (self.dictPy3GblEnv))
        asObjDetail.append("'dictReqHandlerEnv' is [%s]. " % (self.dictReqHandlerEnv))

        return ''.join(asObjDetail)

    def __str__(self):

        return self.toString()

    def __repr__(self):

        return self.toString()

    def reportWIBPlatformDataAsRawJson(self):

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "WIB Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        try:

            bLoadWIBJsonDataFileOk = self.__loadWIBPlatformDataFile()

            if bLoadWIBJsonDataFileOk == False:

                print("%s 'reportWIBPlatformDataAsRawJson()' - The WIB Platform data file failed to load (Strict JSON) - Error!" % (self.dictReqHandlerEnv["sClassDisp"]))
                print("", flush=True)

                dictPy3GblEnv["bProcessingError"] = True

                return False

            bConvertWIBPlatformDataOk = self.__convertWIBPlatformDataToReportLines()

            if bConvertWIBPlatformDataOk == False:
         
                print("%s 'reportWIBPlatformDataAsRawJson()' - The WIB Platform Data failed to convert to Report Line(s) - Error!" % (self.dictReqHandlerEnv["sClassDisp"]))
                print("", flush=True)
         
                dictPy3GblEnv["bProcessingError"] = True
         
                return False

            bOutputWIBPlatformDataToReportPDFOk = self.__outputWIBPlatformReportPDF()
         
            if bOutputWIBPlatformDataToReportPDFOk == False:
         
                print("%s 'reportWIBPlatformDataAsRawJson()' - The WIB Platform report PDF failed to output - Error!" % (self.dictReqHandlerEnv["sClassDisp"]))
                print("", flush=True)
         
                dictPy3GblEnv["bProcessingError"] = True
         
                return False
        
        except Exception as inst:

            print("%s 'reportWIBPlatformDataAsRawJson()' - exception occured..." % (self.dictReqHandlerEnv["sClassDisp"]))
            print(type(inst))
            print(inst)

            excType, excValue, excTraceback = sys.exc_info()
            asTracebackLines                = traceback.format_exception(excType, excValue, excTraceback)

            print("- - - ")
            print('\n'.join(asTracebackLines))
            print("- - - ", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

        return True

    def __loadWIBPlatformDataFile(self):

        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "WIB Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"

        bWIBPlatformDataIsFile = os.path.isfile(self.dictPy3GblEnv["sScriptInputWIBPlatformDataFile"])

        if bWIBPlatformDataIsFile == False:

            print("%s Command received a WIB Platform data filename of [%s] that does NOT exist - Error!" % (self.dictReqHandlerEnv["sClassDisp"], self.dictPy3GblEnv["sScriptInputWIBPlatformDataFile"]))
            print("", flush=True)

            self.dictPy3GblEnv["bProcessingError"] = True

            return False

        try:

            print("%s Reading the (Input) WIB Platform data from the file [%s]..." % (self.dictReqHandlerEnv["sClassDisp"], self.dictPy3GblEnv["sScriptInputWIBPlatformDataFile"]))

            self.dictReqHandlerEnv["dictWIBPlatformData"] = {}

            with open(self.dictPy3GblEnv["sScriptInputWIBPlatformDataFile"], "r") as fWIBPlatformDataFile:

                # Read the entire input:

                rawWIBPlatformData = fWIBPlatformDataFile.read()

                self.dictReqHandlerEnv["dictWIBPlatformData"] = json.loads(rawWIBPlatformData, object_hook=json_util.object_hook)
         
            if self.dictReqHandlerEnv["dictWIBPlatformData"] == None:
         
                print("%s Command has read an (Input) WIB Platform data object that is 'None' - Error!" % (self.dictReqHandlerEnv["sClassDisp"]))

                dictPy3GblEnv["bProcessingError"] = True
         
                return False

            print("")
            print("=============== TYPE 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"]' ===============")
            print(type(self.dictReqHandlerEnv["dictWIBPlatformData"]))
            print("", flush=True)

        #   self.dictReqHandlerEnv["listRawWIBIncidentsData"] = []

            if type(self.dictReqHandlerEnv["dictWIBPlatformData"]) == dict:

                print("%s The (input) WIB Platform 'json' data: LEN (%d) - TYPE [%s] - loaded the object as a dictionary..." % (self.dictReqHandlerEnv["sClassDisp"], len(self.dictReqHandlerEnv["dictWIBPlatformData"]), type(self.dictReqHandlerEnv["dictWIBPlatformData"])))
                print("", flush=True)

            else:

                print("%s The (input) WIB Platform 'json' data: Unknown TYPE [%s] - unable to handle the 'unknown' object TYPE - Error!" % (self.dictReqHandlerEnv["sClassDisp"], type(self.dictReqHandlerEnv["dictWIBPlatformData"])))
                print("", flush=True)

                dictPy3GblEnv["bProcessingError"] = True

                return False
         
            print("")
            print("=============== TYPE 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"]' Dictionary ===============")
            print(type(self.dictReqHandlerEnv["dictWIBPlatformData"]))
         
            print("")
            print("=============== DIR 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"]' Dictionary Object ===============")
            print(dir(self.dictReqHandlerEnv["dictWIBPlatformData"]))
         
            print("")
            print("=============== Object 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"]' Dictionary [RAW print] ===============")
            print(self.dictReqHandlerEnv["dictWIBPlatformData"])
         
            print("%s Command has read an (Input) WIB Platform data from the file [%s] that contains (%d) Dictionary item(s)..." % (self.dictReqHandlerEnv["sClassDisp"], self.dictPy3GblEnv["sScriptInputWIBPlatformDataFile"], len(self.dictReqHandlerEnv["dictWIBPlatformData"])))
            print("", flush=True)

        except Exception as inst:

            print("%s '__loadWIBPlatformDataFile()' - exception occured..." % (self.dictReqHandlerEnv["sClassDisp"]))
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

    def __convertWIBPlatformDataToReportLines(self):
 
        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "WIB Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"
 
        try:
 
            if self.dictReqHandlerEnv["dictWIBPlatformData"]       == None or \
               type(self.dictReqHandlerEnv["dictWIBPlatformData"]) != dict:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s The (Input) WIB Platform data dictionary has a value of None or is NOT of a Dictionary Type - Error!" % (self.dictReqHandlerEnv["sClassDisp"]))
                print("", flush=True)

                return False

            if len(self.dictReqHandlerEnv["dictWIBPlatformData"]) < 1:
 
                print("%s The Dictionary 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"]' contains NO Items - Error!" % (self.dictReqHandlerEnv["sClassDisp"]))
                print("", flush=True)
 
                self.dictPy3GblEnv["bProcessingError"] = True
 
                return False

            # ---------------------------------------------------------------------------------------------------------
            #   dictPy3GblEnv["asScriptWIBPlatformDataReportOrder"] = ["StatisticsAggregated",
            #                                                          "StatisticsDaily",
            #                                                          "Incidents"]
            # ---------------------------------------------------------------------------------------------------------
            
            print("%s Converting the Dictionary 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"]' to a LIST of Report Line(s)..." % (self.dictReqHandlerEnv["sClassDisp"]))

            self.dictReqHandlerEnv["listWIBPlatformReport"] = []
            
            for sWIBPlatformKey in self.dictPy3GblEnv["asScriptWIBPlatformDataReportOrder"]:

                if sWIBPlatformKey != None:

                    sWIBPlatformKey = sWIBPlatformKey.strip()

                if sWIBPlatformKey == None or \
                   len(sWIBPlatformKey) < 1:

                    continue

                if sWIBPlatformKey not in self.dictReqHandlerEnv["dictWIBPlatformData"].keys():

                    continue

                objWIBPlatformValue = self.dictReqHandlerEnv["dictWIBPlatformData"][sWIBPlatformKey]

                if objWIBPlatformValue == None:

                    continue

                if type(objWIBPlatformValue) != dict and \
                   type(objWIBPlatformValue) != list:

                    continue

                self.dictReqHandlerEnv["listWIBPlatformReport"].append("\"%s\"" % (sWIBPlatformKey))
                self.dictReqHandlerEnv["listWIBPlatformReport"].append("")

                listWIBPlatformValues = []

                if sWIBPlatformKey != "Incidents":

                    sWIBPlatformValue     = json.dumps(objWIBPlatformValue, indent=4)
                    listWIBPlatformValues = sWIBPlatformValue.split('\n')

                    self.dictReqHandlerEnv["listWIBPlatformReport"].extend(listWIBPlatformValues)
                    self.dictReqHandlerEnv["listWIBPlatformReport"].append("\f")

                else:

                    if "items" in objWIBPlatformValue.keys():

                        listWIBPlatformIncidents = objWIBPlatformValue["items"]

                        cWIBPlatformIncidents = 0

                        for dictWIBPlatformIncident in listWIBPlatformIncidents:

                            if dictWIBPlatformIncident       == None or \
                               type(dictWIBPlatformIncident) != dict:

                                continue

                            cWIBPlatformIncidents += 1

                            self.dictReqHandlerEnv["listWIBPlatformReport"].append("Incident #(%d) of (%d):" % (cWIBPlatformIncidents, len(listWIBPlatformIncidents)))
                            self.dictReqHandlerEnv["listWIBPlatformReport"].append("")

                            sWIBPlatformValue     = json.dumps(dictWIBPlatformIncident, indent=4)
                            listWIBPlatformValues = sWIBPlatformValue.split('\n')

                            self.dictReqHandlerEnv["listWIBPlatformReport"].extend(listWIBPlatformValues)
                            self.dictReqHandlerEnv["listWIBPlatformReport"].append("\f")

            print("%s Converted the Dictionary 'self.dictReqHandlerEnv[\"dictWIBPlatformData\"]' to a LIST of (%d) Report Line(s)..." % (self.dictReqHandlerEnv["sClassDisp"], len(self.dictReqHandlerEnv["listWIBPlatformReport"])))
            print("", flush=True)

        except Exception as inst:
 
            print("%s '__convertWIBPlatformDataToReportLines()' - exception occured..." % (self.dictReqHandlerEnv["sClassDisp"]))
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
 
    def __outputWIBPlatformReportPDF(self):
 
        assert len(self.dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'dictPy3GblEnv' has NO Element(s) - Fatal!"
        assert len(self.dictReqHandlerEnv) > 0, "WIB Handler Environmental dictionary 'dictReqHandlerEnv' has NO Element(s) - Fatal!"
 
        if dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"] != None:
 
            dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"] = dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"].strip()
 
        if dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"] == None or \
           len(dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"]) < 1:
 
            print("%s The (Output) WIB Incident(s) Report PDF filename is None or Empty - this is required for output - Error!" % (self.dictReqHandlerEnv["sClassDisp"]))
            print("", flush=True)
 
            return False
 
        try:
 
            print("")
            print("=================== WIB Platform 'raw' JSON PDF Output =======================")

            if self.dictReqHandlerEnv["listWIBPlatformReport"]       == None or \
               type(self.dictReqHandlerEnv["listWIBPlatformReport"]) != list:

                self.dictPy3GblEnv["bProcessingError"] = True

                print("%s The WIB Platform Report line(s) List has a value of None or is NOT of a List Type - Error!" % (self.dictReqHandlerEnv["sClassDisp"]))
                print("", flush=True)

                return False

            if len(self.dictReqHandlerEnv["listWIBPlatformReport"]) < 1:
 
                print("%s The List 'self.dictReqHandlerEnv[\"listWIBPlatformReport\"]' contains NO Items - Error!" % (self.dictReqHandlerEnv["sClassDisp"]))
                print("", flush=True)
 
                self.dictPy3GblEnv["bProcessingError"] = True
 
                return False
 
            print("%s '__outputWIBPlatformReportPDF()' - Command is generating the (Output) WIB Platform 'raw' JSON Report PDF file of [%s]..." % (self.dictReqHandlerEnv["sClassDisp"], dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"]))
            print("")
 
            objOutputWIBPlatformReportPDFCanvas = Canvas(dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"], pagesize = LETTER)  
 
            fPageWidth              = LETTER[1]
            sCreatedPDFHeaderImage  = "WIB_header_image.jpg"
            sImagePDFFileSpec       = os.path.realpath(sCreatedPDFHeaderImage)
            bImagePDFFileSpecIsFile = os.path.isfile(sImagePDFFileSpec)
 
            if bImagePDFFileSpecIsFile == False:
 
                print("%s IMAGE file of [%s] does NOT exist - continuing..." % (sScriptDisp, sImagePDFFileSpec))
                print("", flush=True)
 
            else:
 
                print("Drawing into the Canvas the IMAGE file named [%s]..." % (sImagePDFFileSpec))
                print("", flush=True)
 
                objOutputWIBPlatformReportPDFCanvas.drawInlineImage(sImagePDFFileSpec, (1.75 * inch), (6 * inch), (fPageWidth - (6 * inch)), (3 * inch))
 
            sOutputWIBPlatformReportPDFCanvasText     = "=== WIB Platform 'raw' JSON PDF Report ==="
            sOutputWIBPlatformReportPDFCanvasFontName = "Courier"
            iOutputWIBPlatformReportPDFCanvasFontSize = 16
            outputWIBPlatformReportPDFCanvasFillColor = darkcyan
 
            objOutputWIBPlatformReportPDFCanvas.setFont(sOutputWIBPlatformReportPDFCanvasFontName, iOutputWIBPlatformReportPDFCanvasFontSize)  
            objOutputWIBPlatformReportPDFCanvas.setFillColor(outputWIBPlatformReportPDFCanvasFillColor)  
            objOutputWIBPlatformReportPDFCanvas.drawString((1.4 * inch), (5 * inch), sOutputWIBPlatformReportPDFCanvasText)  
 
            dtNow                                      = datetime.now()
            sDTNowStamp                                = dtNow.strftime("%Y/%m/%d at %H:%M:%S")
            sOutputWIBPlatformReportPDFCanvasText     = ("Report creation date on [%s]" % (sDTNowStamp))
 
            objOutputWIBPlatformReportPDFCanvas.drawString((1 * inch), (4.5 * inch), sOutputWIBPlatformReportPDFCanvasText)  
 
            objOutputWIBPlatformReportPDFCanvas.showPage()
 
            sOutputWIBPlatformReportPDFCanvasFontName = "Courier"
            iOutputWIBPlatformReportPDFCanvasFontSize = 12
            outputWIBPlatformReportPDFCanvasFillColor = black
 
            objOutputWIBPlatformReportPDFCanvas.setFont(sOutputWIBPlatformReportPDFCanvasFontName, iOutputWIBPlatformReportPDFCanvasFontSize)  
            objOutputWIBPlatformReportPDFCanvas.setFillColor(outputWIBPlatformReportPDFCanvasFillColor)  
 
            iCurrentMultiplier = 10.6
 
            for sOutputWIBPlatformReportLine in self.dictReqHandlerEnv["listWIBPlatformReport"]:
 
                if sOutputWIBPlatformReportLine != None and \
                   sOutputWIBPlatformReportLine == "\f":
 
                    iCurrentMultiplier = 10.6
 
                    objOutputWIBPlatformReportPDFCanvas.showPage()
                    objOutputWIBPlatformReportPDFCanvas.setFont(sOutputWIBPlatformReportPDFCanvasFontName, iOutputWIBPlatformReportPDFCanvasFontSize)  
                    objOutputWIBPlatformReportPDFCanvas.setFillColor(outputWIBPlatformReportPDFCanvasFillColor)  
 
                    continue
 
                if sOutputWIBPlatformReportLine == None or \
                   len(sOutputWIBPlatformReportLine) < 1:
 
                    sOutputWIBPlatformReportLine = ""
 
                iReportLineLeftSqBracket = sOutputWIBPlatformReportLine.find('[')
 
                if len(sOutputWIBPlatformReportLine) < 82 or \
                   iReportLineLeftSqBracket          < 0:
 
                    objOutputWIBPlatformReportPDFCanvas.drawString((0.3 * inch), (iCurrentMultiplier * inch), sOutputWIBPlatformReportLine)  
 
                    iCurrentMultiplier -= 0.145
 
                    if iCurrentMultiplier <= 0.5:
 
                        iCurrentMultiplier = 10.6
 
                        objOutputWIBPlatformReportPDFCanvas.showPage()
                        objOutputWIBPlatformReportPDFCanvas.setFont(sOutputWIBPlatformReportPDFCanvasFontName, iOutputWIBPlatformReportPDFCanvasFontSize)  
                        objOutputWIBPlatformReportPDFCanvas.setFillColor(outputWIBPlatformReportPDFCanvasFillColor)  
 
                    continue
 
                iReportLineLeftSqBracketIndex = sOutputWIBPlatformReportLine.index('[')
                sOutputWIBPlatformReportLine1 = sOutputWIBPlatformReportLine[:iReportLineLeftSqBracketIndex]
                sOutputWIBPlatformReportLine2 = sOutputWIBPlatformReportLine[iReportLineLeftSqBracketIndex:]
 
                objOutputWIBPlatformReportPDFCanvas.drawString((0.3 * inch), (iCurrentMultiplier * inch), sOutputWIBPlatformReportLine1)  
 
                iCurrentMultiplier -= 0.145
 
                objOutputWIBPlatformReportPDFCanvas.drawString((0.6 * inch), (iCurrentMultiplier * inch), sOutputWIBPlatformReportLine2)  
 
                iCurrentMultiplier -= 0.145
 
                if iCurrentMultiplier <= 0.5:
 
                    iCurrentMultiplier = 10.6
 
                    objOutputWIBPlatformReportPDFCanvas.showPage()
                    objOutputWIBPlatformReportPDFCanvas.setFont(sOutputWIBPlatformReportPDFCanvasFontName, iOutputWIBPlatformReportPDFCanvasFontSize)  
                    objOutputWIBPlatformReportPDFCanvas.setFillColor(outputWIBPlatformReportPDFCanvasFillColor)  
 
            objOutputWIBPlatformReportPDFCanvas.save() 
 
            print("%s '__outputWIBPlatformReportPDF()' - Command has generated the (Output) WIB Platform 'raw' JSON Report PDF file of [%s]..." % (self.dictReqHandlerEnv["sClassDisp"], dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"]))
            print("")
            print("=============================================================================")
            print("", flush=True)
 
        except Exception as inst:
 
            print("%s '__outputWIBPlatformReportPDF()' - exception occured..." % (self.dictReqHandlerEnv["sClassDisp"]))
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
 
def main():

    global dictPy3GblEnv

    # - - - - - TEST - - - - -
    #   dictPy3GblEnv = {}

    assert len(dictPy3GblEnv) > 0, "Default Python3 'Global' Environmental dictionary 'dictPy3GblEnv' has NO Element(s) - Fatal!"

    try:

        dtNow       = datetime.now()
        sDTNowStamp = dtNow.strftime("%Y/%m/%d at %H:%M:%S")

        print("%s The WIB Platform Data 'raw' JSON Reporter #1 is starting execution from Server [%s] on [%s] under Python [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sServerNode"], sDTNowStamp, dictPy3GblEnv["sPythonVers"]))
        print("")

        if dictPy3GblEnv["bPlatformIsWindows"] == True:

            print("%s The platform 'system' of [%s] indicates this is a Microsoft/Windows system..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sPlatform"]))

        else:

            print("%s The platform 'system' is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sPlatform"]))

        dictPy3GblEnv["optParser"].add_option("-v", "--verbose", dest="run_verbose", default=False, help="Run VERBOSE", action="store_true")
        dictPy3GblEnv["optParser"].add_option("-i", "--input-wib-platform-file", dest="input_wib_platform_file", default="", help="(Input) WIB Platform data file", metavar="Input-WIB-Platform-file")
        dictPy3GblEnv["optParser"].add_option("-o", "--output-wib-platform-report-pdf", dest="output_wib_platform_report_pdf", default="", help="(Output) WIB Platform report PDF", metavar="Output-WIB-Platform-Report-PDF")
     
        (options, args) = dictPy3GblEnv["optParser"].parse_args()
     
        dictPy3GblEnv["bVerbose"]                          = options.run_verbose
        dictPy3GblEnv["sScriptInputWIBPlatformDataFile"]   = options.input_wib_platform_file.strip()
        dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"] = options.output_wib_platform_report_pdf.strip()
     
    #   if dictPy3GblEnv["bVerbose"] == True:
     
        print("%s Command VERBOSE flag is [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["bVerbose"]))
        print("")
        print("%s Command (Input)  WIB Platform data file is [%s]..."       % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sScriptInputWIBPlatformDataFile"]))
        print("%s Command (Output) WIB Platform report PDF is [%s]..."      % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"]))
        print("")

        if dictPy3GblEnv["sScriptInputWIBPlatformDataFile"] != None:

            dictPy3GblEnv["sScriptInputWIBPlatformDataFile"] = dictPy3GblEnv["sScriptInputWIBPlatformDataFile"].strip()

        if dictPy3GblEnv["sScriptInputWIBPlatformDataFile"] == None or \
           len(dictPy3GblEnv["sScriptInputWIBPlatformDataFile"]) < 1:

            print("%s The (Input) WIB Platform data filename is None or Empty - this is required - Error!" % (dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return False

        if dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"] != None:

            dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"] = dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"].strip()

        if dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"] == None or \
           len(dictPy3GblEnv["sScriptOutputWIBPlatformReportPDF"]) < 1:

            print("%s The (Output) WIB Platform report PDF filename is None or Empty - this is required for output - Error!" % (dictPy3GblEnv["sScriptDisp"]))
            print("", flush=True)

            return False

        # Invoke the WIB Platform data processing...

        objWIBPlatformReporting = HandleWIBPlatformRawJsonReporting(dictpy3gblenv=dictPy3GblEnv)

        if dictPy3GblEnv["bVerbose"] == True:

            print("%s The 'objWIBPlatformReporting' object after 'init' is [%s]..." % (dictPy3GblEnv["sScriptDisp"], objWIBPlatformReporting.toString()))
            print("", flush=True)

        bReportWIBPlatformOk = objWIBPlatformReporting.reportWIBPlatformDataAsRawJson()

        if dictPy3GblEnv["bVerbose"] == True:

            print("%s The 'objWIBJsonIncidentsScanning' object after 'reportWIBPlatformDataAsRawJson' is [%s]..." % (dictPy3GblEnv["sScriptDisp"], objWIBPlatformReporting.toString()))
            print("", flush=True)

        if bReportWIBPlatformOk == False:

            print("%s The WIB Platform 'raw' JSON 'reporting' process failed - Error!" % (dictPy3GblEnv["sScriptDisp"]))

            dictPy3GblEnv["bProcessingError"] = True

        # Cleanup...

        dtNow       = datetime.now()
        sDTNowStamp = dtNow.strftime("%Y/%m/%d at %H:%M:%S")

        print("")
        print("%s The WIB Platform Data 'raw' JSON Reporter #1 is ending execution from Server [%s] on [%s] under Python [%s]..." % (dictPy3GblEnv["sScriptDisp"], dictPy3GblEnv["sServerNode"], sDTNowStamp, dictPy3GblEnv["sPythonVers"]))
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

    if dictPy3GblEnv["bProcessingError"] == True:

        return False

    return True

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
        print("- - - ", flush=True)

        sys.exit(99)

    bCmdExecOk  = main()

    dtNow       = datetime.now()
    sDTNowStamp = dtNow.strftime("%Y/%m/%d at %H:%M:%S")
    tmEndTime   = time.time()
    tmElapsed   = (tmEndTime - dictPy3GblEnv["tmStartTime"])
    sTMElapsed  = time.strftime("%H:%M:%S", time.gmtime(tmElapsed))

    print("%s The WIB Platform Data 'raw' JSON Reporter #1 is ending execution with an 'elapsed' time of [%3d:%s - (%f)]..." % (dictPy3GblEnv["sScriptDisp"], (tmElapsed // 86400), sTMElapsed, tmElapsed))
    print("", flush=True)

    if bCmdExecOk                        == False or \
       dictPy3GblEnv["bProcessingError"] == True:

        print("%s Exiting with a Return Code of (31)..." % (dictPy3GblEnv["sScriptDisp"]))
        print("", flush=True)

        sys.exit(31)

    print("%s Exiting with a Return Code of (0)..." % (dictPy3GblEnv["sScriptDisp"]))
    print("", flush=True)

    sys.exit(0)

