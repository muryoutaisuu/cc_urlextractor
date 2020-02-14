import os
import sys # for early exit

import splunk.Intersplunk
import re

import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

################################################################################
# OPTIONS
# url=<urlfield> # use this field as the field with the urls. defaults to url
# noue # do not create the prefix 'ue_'
# debug # used for testing this python script
# fields="<comma separated list of fields>" # only this fields shall be returned
#   protocol
#   method
#   uri
#   path
#   document
#   folldomain
#   subdomains
#   domain
#   highdomain
#   variables
#   <variables from url>


################################################################################
# ERRORCODS
#   3:	No URL to extract fields from, whether from user nor the default fields exist

################################################################################
# SETUP LOGGER

def setup_logging():
   """ initialize the logging handler """
   logger = logging.getLogger('splunk.urlextractor')
   SPLUNK_HOME = os.environ['SPLUNK_HOME']
   LOGGING_DEFAULT_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log.cfg')
   LOGGING_LOCAL_CONFIG_FILE = os.path.join(SPLUNK_HOME, 'etc', 'log-local.cfg')
   LOGGING_STANZA_NAME = 'python'
   LOGGING_FILE_NAME = "urlextractor.log"
   BASE_LOG_PATH = os.path.join('var', 'log', 'splunk')
   LOGGING_FORMAT = "%(asctime)s %(levelname)-s\t%(module)s:%(lineno)d - %(message)s"
   splunk_log_handler = logging.handlers.RotatingFileHandler(os.path.join(SPLUNK_HOME, BASE_LOG_PATH, LOGGING_FILE_NAME), mode='a')
   splunk_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT))
   logger.addHandler(splunk_log_handler)
   splunk.setupSplunkLogger(logger, LOGGING_DEFAULT_CONFIG_FILE, LOGGING_LOCAL_CONFIG_FILE, LOGGING_STANZA_NAME)
   return logger

logger = setup_logging()

################################################################################
# METHODS, FUNCTIONS

################################################################################
# MAIN

def main():
  
  ################
  ## SET VARIABLES
 
  fldurl = "url" # set again below
  fldurlfinder = "uf_url" # outputfield of urlfinder
  keywords,kvs = splunk.Intersplunk.getKeywordsAndOptions()
  results = splunk.Intersplunk.readResults(None, None, True)
  DEBUG = False
  UEPRE = "ue_"
  RETURNALL = True
  FIELDS = ["protocol","uri","path","document","fulldomain","subdomains","highdomain","variables","method"]
  METHODS = ["GET","POST","PUT","DELETE"]
  fields = []
  DECODE = True

  ##################
  ## CHECK VARIABLES

  if len(results) < 1:
    logger.debug("results=\"\" exit=true results=\"<1\"")
    sys.exit(0)
    # do not know why, but sometimes splunk would call this script more than once
    # and always with with a lot of empty results before the actual data

  # used for testing new features
  if "debug" in keywords:
    DEBUG=True
    logger.debug("DEBUGMODE=true message=\"Testing new Features\"")

  if "noue" in keywords:
    UEPRE=""
    logger.info("NOUE=true")

  if "nodecode" in keywords:
    DECODE = False
  else:
    import urllib

  if "fields" in kvs:
    fields=kvs["fields"].split(",")
    RETURNALL = False
    logger.debug("OUTPUT=true Fields=\""+str(fields)+"\"")

  # did user give a url?
  if "url" in kvs:
    fldurl = kvs["url"]
    logger.debug("results="+str(results))
    if not (fldurl in results[0]):
      logger.critical("NOURL=true message=\"User given field not in results\" field="+fldurl)
      sys.exit(3)
    else:
      logger.debug("URLFOUND=true message=\"User given URL in results\" field="+fldurl)
  else:
    if ("url" in results[0]):
      fldurl = "url"
      logger.debug("URLFOUND=true message=\"Default URL in results\" field="+fldurl)
    elif (fldurlfinder in results[0]):
      fldurl = "uf_url"
      logger.debug("URLFOUND=true message=\"Default URL in results\" field="+fldurl)
    else:
      logger.critical("NOURL=true message=\"Default URL not in results\" field="+fldurl)
      sys.exit(3)
  
  #############################
  #############################
  ## ITERATE THROUGH EACH EVENT

  ################
  ## SET VARIABLES

  url = ""
  strex = ur"^((?P<method>\w+)\s+)?((?P<protocol>\w+)://)?(?P<domain>(\w+\.)*\w+)?(?P<uri>\S+)?"
  rex = re.compile(strex)

  ###########
  ## ITERATOR

  for res in results:
    
    ################
    ## SET VARIABLES

    url = res[fldurl]
    matchfound = False
      
    ##################
    ## CHECK VARIABLES

    if len(url) <= 0:
      logger.info("URLEMPTY=true message=\"url is empty. Will not process anything and return no fields\" event=\"["+str(res)+"]\"")
      continue

    #if DECODE:
      #url = urllib.unquote(url)

    logger.debug("URL="+url)

    ##############
    ##############
    ## PROCESS URL

    # if no url provided in fldurl, and only the method exists, the regex does something wrong and will return method as domain, this two line escape that phenomenon
    if (res[fldurl] in METHODS):
      continue
      pass

    match = re.match(strex, url)

    # test whether match exists
    if match:
      matchfound = True
      urifound = True
      if match.group("uri") == None or len(match.group("uri")) <= 0:
        urifound = False
        logger.info("message=\"URI not found\"")

      if RETURNALL or "method" in fields:
        res[UEPRE+"method"] = match.group("method")
      if RETURNALL or "protocol" in fields:
        res[UEPRE+"protocol"] = match.group("protocol")
      if RETURNALL or "uri" in fields:
        if DECODE and urifound:
          res[UEPRE+"uri"] = urllib.unquote(match.group("uri"))
        elif urifound:
          res[UEPRE+"uri"] = match.group("uri")
      if RETURNALL or ("fulldomain" in fields) or ("subdomains" in fields) or ("domain" in fields) or ("highdomain" in fields):
        fulldomain = match.group("domain")

        # distinguish fulldomain, if it exists and if wanted
        if fulldomain != None and (RETURNALL or ("fulldomain" in fields) or ("subdomains" in fields) or ("domain" in fields) or ("highdomain" in fields)):
          res[UEPRE+"fulldomain"] = fulldomain
          if RETURNALL or ("subdomains" in fields) or ("domain" in fields) or ("highdomain" in fields):
            domains = fulldomain.split(".")
            count = len(domains)
            if count == 1 and (RETURNALL or "domain" in fields):
              res[UEPRE+"domain"] = domains[0]
            elif count == 2 and (RETURNALL or "domain" in fields or "highdomain" in fields):
              if RETURNALL or "domain" in fields:
                res[UEPRE+"domain"] = domains[0]
              if RETURNALL or "highdomain" in fields:
                res[UEPRE+"highdomain"] = domains[1]
            elif count > 2 and (RETURNALL or "subdomains" in fields or "domain" in fields or "highdomain" in fields):
              if RETURNALL or "subdomains" in fields:
                tmp  = ""
                for i in range(count-2):
                  tmp = tmp + domains[i]+"."
                res[UEPRE+"subdomains"] = tmp 
              if RETURNALL or "domain" in fields:
                res[UEPRE+"domain"] = domains[count-2]
              if RETURNALL or "highdomain" in fields:
                res[UEPRE+"highdomain"] = domains[count-1]
      if urifound:
        uri = match.group("uri")
        if RETURNALL or "path" in fields or "document" in fields:
        #if RETURNALL or "path" in fields or "document" in fields or "variables" in fields:
          logger.debug("uri="+str(uri))
          pathstrex = ur'^(?P<path>((/\w+/)(\w+/)*)?)(?P<document>(\w|\.|\-|\_)*)'
          pathmatch = re.match(pathstrex,uri)
          if pathmatch:
            if RETURNALL or "path" in fields:
              if DEBUG:
                res[UEPRE+"path"] = urllib.unquote(pathmatch.group("path"))
              else:
                res[UEPRE+"path"] = pathmatch.group("path")
            if RETURNALL or "document" in fields:
              if DEBUG:
                res[UEPRE+"document"] = urllib.unquote(pathmatch.group("document"))
              else:
                res[UEPRE+"document"] = pathmatch.group("document")

        # parse variables from url into new fields
        variablestrex = ur'^[^?]*\?(?P<variables>\S+)'
        variablematch = re.match(variablestrex,uri)
        logger.debug("uri="+uri)
        if variablematch:
          logger.debug("Variables match")
          variables = variablematch.group("variables")
          #logger.debug("VARIABLES: "+variables)
          if RETURNALL or "variables" in fields:
            if DECODE:
              res[UEPRE+"variables"] = urllib.unquote(variables)
            else:
              res[UEPRE+"variables"] = variables
          if len(variables) > 0:
            varsplit = variables.split('&')
            logger.debug("variables="+str(variables))
            logger.debug("varsplit="+str(varsplit))
            for touple in varsplit:
              arrtouple = touple.split('=')
              if RETURNALL or arrtouple[0] in fields:
                if len(arrtouple) > 1:
                  if DECODE:
                  #logger.debug("
                    res[UEPRE+arrtouple[0]] = urllib.unquote(arrtouple[1])
                  else:
                    res[UEPRE+arrtouple[0]] = arrtouple[1]
                else:
                  logger.debug("OUTPUT=true message=\"Variable without value found\" variable="+arrtouple[0])
                  res[UEPRE+arrtouple[0]] = ""
        continue

    if not matchfound:
      logger.warning("NOMATCH: Regex did not match with url: ["+url+"]")
    
    #########
    ## OUTPUT

  splunk.Intersplunk.outputResults(results)
if __name__ == "__main__":
  tstart = datetime.now()
  ID = str(tstart.year)+str(tstart.month)+str(tstart.day)+str(tstart.hour)+str(tstart.minute)+str(tstart.second)+str(tstart.microsecond)
  logger.debug("NEWRUN: ############### ID: "+ID)
  main()
  tend = datetime.now()
  period = tend - tstart
  logger.info("FINISHED: Successfully. Duration in Microseconds: "+str(period.microseconds))
#| inputlookup data.csv | urlextractor debug url=methodurl
